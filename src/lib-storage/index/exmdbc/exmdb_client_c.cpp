#include "exmdb_client_c.h"

#include <iconv.h>
#include <inttypes.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#include <gromox/rop_util.hpp>
#include <map>
#include <sstream>

enum mail_flags {
	MAIL_ANSWERED	= 0x01,
	MAIL_FLAGGED	= 0x02,
	MAIL_DELETED	= 0x04,
	MAIL_SEEN	= 0x08,
	MAIL_DRAFT	= 0x10,
	MAIL_RECENT	= 0x20,

	MAIL_FLAGS_MASK = 0x3f,
	MAIL_FLAGS_NONRECENT = (MAIL_FLAGS_MASK ^ MAIL_RECENT)
};

enum exmdbc_fetch_field {
	MAIL_FETCH_FLAGS		= 0x00000001,
	MAIL_FETCH_MESSAGE_PARTS	= 0x00000002,

	MAIL_FETCH_STREAM_HEADER	= 0x00000004,
	MAIL_FETCH_STREAM_BODY		= 0x00000008,

	MAIL_FETCH_DATE			= 0x00000010,
	MAIL_FETCH_RECEIVED_DATE	= 0x00000020,
	MAIL_FETCH_SAVE_DATE		= 0x00000040,
	MAIL_FETCH_PHYSICAL_SIZE	= 0x00000080,
	MAIL_FETCH_VIRTUAL_SIZE		= 0x00000100,

	/* Set has_nuls / has_no_nuls fields */
	MAIL_FETCH_NUL_STATE		= 0x00000200,

	MAIL_FETCH_STREAM_BINARY	= 0x00000400,

	/* specials: */
	MAIL_FETCH_IMAP_BODY		= 0x00001000,
	MAIL_FETCH_IMAP_BODYSTRUCTURE	= 0x00002000,
	MAIL_FETCH_IMAP_ENVELOPE	= 0x00004000,
	MAIL_FETCH_FROM_ENVELOPE	= 0x00008000,
	MAIL_FETCH_HEADER_MD5		= 0x00010000,
	MAIL_FETCH_STORAGE_ID		= 0x00020000,
	MAIL_FETCH_UIDL_BACKEND		= 0x00040000,
	MAIL_FETCH_MAILBOX_NAME		= 0x00080000,
	MAIL_FETCH_SEARCH_RELEVANCY	= 0x00100000,
	MAIL_FETCH_GUID			= 0x00200000,
	MAIL_FETCH_POP3_ORDER		= 0x00400000,
	MAIL_FETCH_REFCOUNT		= 0x00800000,
	MAIL_FETCH_BODY_SNIPPET		= 0x01000000,
	MAIL_FETCH_REFCOUNT_ID		= 0x02000000,
};

enum mailbox_info_flags {
	MAILBOX_NOSELECT		= 0x001,
	MAILBOX_NONEXISTENT		= 0x002,
	MAILBOX_CHILDREN		= 0x004,
	MAILBOX_NOCHILDREN		= 0x008,
	MAILBOX_NOINFERIORS		= 0x010,
	MAILBOX_MARKED			= 0x020,
	MAILBOX_UNMARKED		= 0x040,
	MAILBOX_SUBSCRIBED		= 0x080,
	MAILBOX_CHILD_SUBSCRIBED	= 0x100,
	MAILBOX_CHILD_SPECIALUSE	= 0x200,

	/* Internally used by lib-storage, use mailbox_info.special_use
	   to actually access these: */
	MAILBOX_SPECIALUSE_ALL		= 0x00010000,
	MAILBOX_SPECIALUSE_ARCHIVE	= 0x00020000,
	MAILBOX_SPECIALUSE_DRAFTS	= 0x00040000,
	MAILBOX_SPECIALUSE_FLAGGED	= 0x00080000,
	MAILBOX_SPECIALUSE_JUNK		= 0x00100000,
	MAILBOX_SPECIALUSE_SENT		= 0x00200000,
	MAILBOX_SPECIALUSE_TRASH	= 0x00400000,
	MAILBOX_SPECIALUSE_IMPORTANT	= 0x00800000,
#define MAILBOX_SPECIALUSE_MASK		  0x00ff0000

	/* Internally used by lib-storage: */
	MAILBOX_SELECT			= 0x20000000,
	MAILBOX_MATCHED			= 0x40000000
};

// FILETIME → time_t (Unix epoch)
static inline time_t filetime_to_time_t(uint64_t filetime)
{
	return (time_t)((filetime - 116444736000000000ULL) / 10000000ULL);
}
static uint64_t unix_time_to_filetime(time_t t) {
	// FILETIME: 100ns ticks since Jan 1, 1601
	// Unix time: seconds since Jan 1, 1970
	const uint64_t EPOCH_DIFF = 11644473600ULL; // seconds
	return ((uint64_t)t + EPOCH_DIFF) * 10000000ULL;
}

#define ADD_STR(tag, field) \
	if ((props->field) && *(props->field)) { \
		pv.push_back({ tag, (void*)props->field }); \
	}

#define ADD_U32(tag, val) \
	{ uint32_t v = (props->val); pv.push_back({ tag, (void*)&v }); }

#define ADD_FLAGS(tag, val) \
	{ uint32_t v = (props->val); pv.push_back({ tag, (void*)&v }); }

#define ADD_FILETIME(tag, field) \
	if (props->field) { \
		uint64_t ft = unix_time_to_filetime(props->field); \
		pv.push_back({ tag, (void*)&ft }); \
	}


using gromox::exmdb_client_remote;

using LLU = unsigned long long;

extern "C" {

struct exmdb_client {
	exmdb_client_remote *impl;
	const char *dir;
};

char *get_utf8_from_props(const struct TPROPVAL_ARRAY *props, uint32_t tag_unicode, uint32_t tag_ansi) {
	const void *raw = props->getval(tag_unicode);

	if (true)
		return (char *)raw;
	if (raw) {
		const unsigned char *p = (const unsigned char*)raw;
		bool is_utf16le = false;
		size_t ascii_count = 0, zero_count = 0;
		for (size_t i = 0; i < 16; ++i) {
			if (p[i] == 0) zero_count++;
			if ((p[i] >= 0x20 && p[i] < 0x7F) || p[i] == 0) ascii_count++;
		}
		if (zero_count >= 6) is_utf16le = true;
		if (!is_utf16le) {
			// fallback: treat as ANSI
			return strdup((const char*)raw);
		} else {
			const uint16_t *wstr = (const uint16_t *)raw;
			size_t wlen = 0;
			while (wstr[wlen]) ++wlen;
			size_t inbytes = wlen * 2;
			size_t outbytes = inbytes * 3 + 1;
			char *utf8 = (char *)malloc(outbytes);
			if (utf8 && utf16le_to_utf8(wstr, inbytes, utf8, outbytes)) {
				return utf8;
			}
			free(utf8);
		}
	}
	//STRING8(ANSI)
	const char *aval = (const char *)props->getval(tag_ansi);
	if (aval) {
		return strdup(aval);
	}
	return NULL;
}

int exmdb_client_create(struct exmdb_client **client_ptr) {
	fprintf(stderr, "[EXMDB] exmdbc_client_ping_store client is local\n");
	if (!client_ptr)
		return EXIT_FAILURE;

	try {
		*client_ptr = new exmdb_client();
		gromox::exmdb_client.emplace(1, 1);

		// NOLINTNEXTLINE(clang-diagnostic-error)
		if (gromox::exmdb_client_run(PKGSYSCONFDIR) != 0) {
			delete *client_ptr;
			*client_ptr = nullptr;
			return EXIT_FAILURE;
		}

		if (!gromox::exmdb_client.has_value()) {
			delete *client_ptr;
			*client_ptr = nullptr;
			return EXIT_FAILURE;
		}

		(*client_ptr)->impl = &gromox::exmdb_client.value();
		return EXIT_SUCCESS;

	} catch (...) {
		if (client_ptr)
			*client_ptr = nullptr;
		return EXIT_FAILURE;
	}
}

void exmdb_client_free(struct exmdb_client **client_ptr) {
	if (client_ptr && *client_ptr) {
		gromox::exmdb_client.reset();
		delete *client_ptr;
		*client_ptr = nullptr;
	}
}

int exmdbc_client_ping_store(const char *dir)
{
	fprintf(stderr, "[EXMDBC] exmdbc_client_ping_store client is remote\n");
	return exmdb_client_remote::ping_store(dir);
}


int exmdbc_client_create_folder_v1(struct exmdb_client *client,
	const char *dir,
	int cpid,
	struct TPROPVAL_ARRAY *pproperties,
	unsigned long *folder_id)
{
	return exmdb_client_remote::create_folder_v1(dir, static_cast<cpid_t>(cpid), pproperties, folder_id);
}

int exmdbc_client_get_folders_dtos(struct exmdb_client *client,
	struct exmdbc_folder_dto *out_array,
	const char *username, unsigned int max_count,
	unsigned int *out_count)
{
	fprintf(stderr, "[EXMDB] exmdbc_client_get_folders_dtos called\n");
	*out_count = 0;
	if (client == nullptr || username == nullptr) {
		fprintf(stderr, "[EXMDB] Invalid arguments\n");
		return -1;
	}

	STORE_ENTRYID store = {0, 0, 0, 0, {}, 0, deconst(""), deconst("")};
	store.wrapped_provider_uid = g_muidStorePrivate;
	store.pmailbox_dn = deconst(username);
	store.pserver_name = deconst(username);
	char *eid = nullptr;
	unsigned int user_id = 0, domain_id = 0;

	if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
		fprintf(stderr, "[EXMDB] store_eid_to_user failed for user: %s\n", username);
		return -1;
	}
	uint64_t fid = 0;
	auto empty_idset = idset::create(idset::type::id_packed);

	uint32_t table_id = 0, row_count = 0;
	fid = rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE);
	BOOL ret = exmdb_client_remote::load_hierarchy_table(eid, fid, nullptr, 0, nullptr, &table_id, &row_count);
	if (ret != TRUE) {
		fprintf(stderr, "[EXMDB] load_hierarchy_table failed for eid=%s\n", eid);
		delete eid;
		return -1;
	}

	static constexpr uint32_t ftags[] = {PidTagFolderId, PR_DISPLAY_NAME, PR_FOLDER_PATHNAME};
	static constexpr PROPTAG_ARRAY ftaghdr = {std::size(ftags), deconst(ftags)};
	tarray_set rowset{};
	if (!exmdb_client_remote::query_table(eid, nullptr, CP_UTF8, table_id,
		&ftaghdr, 0, row_count, &rowset)) {
		fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
		}
	exmdb_client_remote::unload_table(eid, table_id);
	for (const auto &row : rowset) {
		auto name = get_utf8_from_props(&row, PR_DISPLAY_NAME, PR_DISPLAY_NAME_A);
		auto pathname = get_utf8_from_props(&row, PR_FOLDER_PATHNAME, 0);
		// auto content_count = row.get<const uint32_t>(PR_CONTENT_COUNT);
		auto folder_id = row.get<const uint64_t>(PidTagFolderId);

		// fprintf(stderr, "[EXMDB] folder name: %s,  folder pathname: %s\n", name, pathname);

		if (name == nullptr)
			continue;

		struct exmdbc_folder_dto &dto = out_array[(*out_count)++];
		dto.name = name;
		// dto.content_count = content_count;
		dto.flags = 0; // MAILBOX_NOSELECT;
		if (fid == rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT))
			dto.flags |= MAILBOX_SPECIALUSE_DRAFTS;

		if (fid == rop_util_make_eid_ex(1, PRIVATE_FID_SENT_ITEMS))
			dto.flags |= MAILBOX_SPECIALUSE_SENT;

		if (fid == rop_util_make_eid_ex(1, PRIVATE_FID_JUNK))
			dto.flags |= MAILBOX_SPECIALUSE_JUNK;

		if (fid == rop_util_make_eid_ex(1, PRIVATE_FID_DELETED_ITEMS))
			dto.flags |= MAILBOX_SPECIALUSE_TRASH;

		if (fid == rop_util_make_eid_ex(1, PRIVATE_FID_INBOX))
			dto.flags |= MAILBOX_SELECT;
		dto.folder_id = static_cast<unsigned long long>(rop_util_get_gc_value(*folder_id));
	}

	// Free memory
	delete eid;

	return 0;
}


int exmdbc_client_get_folder_dtos(struct exmdb_client *client, uint64_t folder_id, struct exmdb_folder_metadata *folder_metadata, const char *username)
{

	fprintf(stderr, "[EXMDB] exmdbc_client_get_folder_dtos called\n");
	if (client == nullptr || username == nullptr) {
		fprintf(stderr, "[EXMDB] Invalid arguments\n");
		return -1;
	}

	STORE_ENTRYID store = {0, 0, 0, 0, {}, 0, deconst(""), deconst("")};
	store.wrapped_provider_uid = g_muidStorePrivate;
	store.pmailbox_dn = deconst(username);
	store.pserver_name = deconst(username);
	char *eid = nullptr;
	unsigned int user_id = 0, domain_id = 0;

	if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
		fprintf(stderr, "[EXMDB] store_eid_to_user failed for user: %s\n", username);
		return -1;
	}

	uint64_t eid_folder = rop_util_make_eid_ex(1, folder_id);

	static constexpr uint32_t ftags2[] = {PR_CONTENT_COUNT, PR_ASSOC_CONTENT_COUNT, PR_FOLDER_CHILD_COUNT, PR_CHANGE_KEY};
	static constexpr PROPTAG_ARRAY ftaghdr2 = {std::size(ftags2), deconst(ftags2)};
	TPROPVAL_ARRAY props{};
	if (!exmdb_client_remote::get_folder_properties(eid, CP_UTF8, eid_folder, &ftaghdr2, &props)) {
		fprintf(stderr, "fid 0x%llx get_folder_props failed\n", LLU{eid_folder});
		return -1;
	}
	auto pnum = props.get<const uint32_t>(PR_CONTENT_COUNT);
	auto panum = props.get<const uint32_t>(PR_ASSOC_CONTENT_COUNT);
	auto pcnum = props.get<const uint32_t>(PR_FOLDER_CHILD_COUNT);
	auto pmodseq = props.get<uint64_t>(PR_CHANGE_KEY);



	folder_metadata->num_messages = pnum ? *pnum : 0;
	folder_metadata->modseq = pmodseq ? *pmodseq : 1;
	folder_metadata->uidvalidity = 1;
	folder_metadata->uidnext = 1;

	// Free memory
	delete eid;
	return 0;
}

void exmdb_client_set_dir(struct exmdb_client *client, const char *dir)
{
	if (client != nullptr) {
		client->dir = dir != nullptr ? strdup(dir) : nullptr;
	}
}

void set_body_html_from_props(const TPROPVAL_ARRAY *props, struct message_properties *msgs_props) {
	const BINARY *html_bin = (const BINARY *)props->getval(PR_HTML);
	if (html_bin && html_bin->cb > 0 && html_bin->pc) {
		char *html_copy = (char *)malloc(html_bin->cb + 1);
		if (html_copy) {
			memcpy(html_copy, html_bin->pc, html_bin->cb);
			html_copy[html_bin->cb] = '\0';
			msgs_props->body_html = html_copy;
		} else {
			msgs_props->body_html = NULL;
		}
	} else {
		msgs_props->body_html = NULL;
	}
}

int exmdbc_read_message_metadata(uint64_t message_id, struct TPROPVAL_ARRAY *props, struct message_properties *msgs_props)
{
	msgs_props->mid					= message_id;
	msgs_props->from_name			= static_cast<const char *>(props->getval(PR_SENDER_NAME));
	msgs_props->from_email			= static_cast<const char *>(props->getval(PR_SENDER_EMAIL_ADDRESS));
	msgs_props->to_name				= static_cast<const char *>(props->getval(PR_DISPLAY_TO));
	msgs_props->to_email			= static_cast<const char *>(props->getval(PR_EMAIL_ADDRESS));
	msgs_props->cc					= static_cast<const char *>(props->getval(PR_DISPLAY_CC));
	msgs_props->bcc					= static_cast<const char *>(props->getval(PR_DISPLAY_BCC));
	msgs_props->subject				= static_cast<const char *>(props->getval(PR_SUBJECT));
	msgs_props->reply_recipment		= static_cast<const char *>(props->getval(PR_REPLY_RECIPIENT_NAMES));
	msgs_props->reply_to			= static_cast<const char *>(props->getval(PR_IN_REPLY_TO_ID));
	msgs_props->msg_id				= static_cast<const char *>(props->getval(PR_INTERNET_MESSAGE_ID));

	msgs_props->message_header = static_cast<const char *>(props->getval(PR_TRANSPORT_MESSAGE_HEADERS));

	msgs_props->body_plain = static_cast<const char *>(props->getval( PR_BODY));

	set_body_html_from_props(props, msgs_props);

	if (msgs_props->body_plain != nullptr)
		msgs_props->body_size = strlen(msgs_props->body_plain);

	const void *size_val = props->getval(PR_MESSAGE_SIZE);
	msgs_props->size = size_val != nullptr ? *static_cast<const uint32_t *>(size_val) : 0;

	const void *submited_time_val = props->getval(PR_CLIENT_SUBMIT_TIME);
	msgs_props->submited_time = filetime_to_time_t(submited_time_val ? *reinterpret_cast<const uint64_t *>(submited_time_val) : 0);
	const void *delivery_time_val = props->getval(PR_MESSAGE_DELIVERY_TIME);
	msgs_props->delivery_time = filetime_to_time_t(delivery_time_val ? *reinterpret_cast<const uint64_t *>(delivery_time_val) : 0);


	const uint32_t* flags_ptr = static_cast<const uint32_t*>(props->getval(PR_MESSAGE_FLAGS));
	uint32_t flags = (flags_ptr != nullptr) ? *flags_ptr : 0;
	if (flags & MSGFLAG_UNSENT /* 0x8 */)
		msgs_props->flags += MAIL_DRAFT;
	if (flags & MSGFLAG_READ /* 0x1 */)
		msgs_props->flags += MAIL_SEEN;

	const auto flag_status = props->get<const uint32_t>(PR_FLAG_STATUS);
	if (flag_status != nullptr && *flag_status == followupFlagged /* 0x2 */)
		msgs_props->flags += MAIL_FLAGGED;

	const auto *icon_index  = props->get<const uint32_t>(PR_ICON_INDEX);
	if (icon_index != nullptr && *icon_index == MAIL_ICON_REPLIED /* 0x105 */)
		msgs_props->flags += MAIL_ANSWERED;

	//TODO:EMXDBC: Not found analogue.
	// if (icon_index != nullptr && *icon_index == MAIL_ICON_FORWARDED /* 0x106 */)
	// 	msgs_props->flags += "$Forwarded";

	// There is Deleted in IMAP\Dovecot but not in MAPI so i skipping it for reading and when writing i will need to delete it before saving. (Need to discuss with Jan)
	return 0;
}

int exmdbc_client_get_message_properties(struct exmdb_client *client, uint64_t folder_id, uint64_t message_id, const char *username, struct message_properties *msgs_props, uint32_t fields)
{
	fprintf(stderr, "[EXMDB] exmdbc_client_get_message_properties called\n");
    if (!client || !username || !msgs_props) {
        fprintf(stderr, "[EXMDB] Invalid arguments to get_message_properties\n");
        return -1;
    }

    STORE_ENTRYID store = {0, 0, 0, 0, {}, 0, deconst(""), deconst("")};
    store.wrapped_provider_uid = g_muidStorePrivate;
    store.pmailbox_dn = deconst(username);
    store.pserver_name = deconst(username);

    char *eid = nullptr;
    unsigned int user_id = 0, domain_id = 0;
    if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
        fprintf(stderr, "[EXMDB] Failed to resolve store EID for %s\n", username);
        return -1;
    }

    uint64_t eid_folder = rop_util_make_eid_ex(1, folder_id);

	std::vector<uint32_t> tags;
	tags.push_back(PidTagMid);

	// FLAGS
	if (fields & MAIL_FETCH_FLAGS) {
	    tags.push_back(PR_MESSAGE_FLAGS);
	    tags.push_back(PR_FLAG_STATUS);
	    tags.push_back(PR_ICON_INDEX);
	}

	// SIZE
	if (fields & MAIL_FETCH_PHYSICAL_SIZE) tags.push_back(PR_MESSAGE_SIZE);
	if (fields & MAIL_FETCH_VIRTUAL_SIZE)  tags.push_back(PR_MESSAGE_SIZE);

	// DATES
	if (fields & MAIL_FETCH_DATE)          tags.push_back(PR_CLIENT_SUBMIT_TIME);
	if (fields & MAIL_FETCH_RECEIVED_DATE) tags.push_back(PR_MESSAGE_DELIVERY_TIME);

	// ENVELOPE
	if (fields & MAIL_FETCH_IMAP_ENVELOPE) {
	    tags.push_back(PR_SENDER_NAME);
	    tags.push_back(PR_SENDER_EMAIL_ADDRESS);
	    tags.push_back(PR_DISPLAY_TO);
	    tags.push_back(PR_EMAIL_ADDRESS);
	    tags.push_back(PR_DISPLAY_CC);
	    tags.push_back(PR_DISPLAY_BCC);
	    tags.push_back(PR_SUBJECT);
	    tags.push_back(PR_REPLY_RECIPIENT_NAMES);
	    tags.push_back(PR_IN_REPLY_TO_ID);
	    tags.push_back(PR_INTERNET_MESSAGE_ID);
	}

	// BODYSTRUCTURE or BODY
	if (fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) {
	    tags.push_back(PR_BODY);
	    tags.push_back(PR_BODY_HTML);
	}
	if (fields & MAIL_FETCH_STREAM_BODY) {
		tags.push_back(PR_BODY);
		tags.push_back(PR_BODY_HTML);
	}
	if (fields & MAIL_FETCH_IMAP_BODY) {
		tags.push_back(PR_BODY);
		tags.push_back(PR_BODY_HTML);
	}

	// STREAM HEADER (RFC822)
	if (fields & MAIL_FETCH_STREAM_HEADER) {
	    tags.push_back(PR_SENDER_NAME);
	    tags.push_back(PR_SENDER_EMAIL_ADDRESS);
	    tags.push_back(PR_DISPLAY_TO);
	    tags.push_back(PR_EMAIL_ADDRESS);
	    tags.push_back(PR_DISPLAY_CC);
	    tags.push_back(PR_DISPLAY_BCC);
	    tags.push_back(PR_SUBJECT);
	    tags.push_back(PR_IN_REPLY_TO_ID);
	    tags.push_back(PR_INTERNET_MESSAGE_ID);
	    tags.push_back(PR_CLIENT_SUBMIT_TIME);
	    tags.push_back(PR_TRANSPORT_MESSAGE_HEADERS);
	}

	std::sort(tags.begin(), tags.end());
	tags.erase(std::unique(tags.begin(), tags.end()), tags.end());

    PROPTAG_ARRAY tag_array = {
        (uint16_t)tags.size(),
        deconst(tags.data())
    };

	if (std::find(tags.begin(), tags.end(), PR_BODY) != tags.end() || std::find(tags.begin(), tags.end(),PR_BODY_HTML) != tags.end())
	{
    	int ret = -1;
    	uint64_t eid_message = rop_util_make_eid_ex(1, message_id);
    	MESSAGE_CONTENT *content = nullptr;
    	BOOL ok = exmdb_client_remote::read_message(eid, username, CP_UTF8, eid_message, &content);
    	if (ok == TRUE && content != nullptr) {
    		exmdbc_read_message_metadata(message_id, content->get_proplist(), msgs_props);
    		ret	= 0;
    	}

    	delete eid;
    	delete content;
    	return ret;
	}

	int ret = 0;
    uint32_t table_id = 0;
    uint32_t row_count = 0;

    if (!exmdb_client_remote::load_content_table(eid, CP_UTF8, eid_folder,
			username, 0, nullptr, nullptr, &table_id, &row_count))
    {
    	fprintf(stderr, "[EXMDBC] load_content_table failed for folder %" PRIu64 "\n", folder_id);

    	delete eid;
    	return -1;
	}

    TARRAY_SET tset{};
    if (!exmdb_client_remote::query_table(eid, nullptr, CP_UTF8, table_id,
										 &tag_array, 0, row_count, &tset))
    {
    	fprintf(stderr, "[EXMDBC] query_table failed\n");
    	exmdb_client_remote::unload_table(eid, table_id);

    	delete eid;
    	return -1;
	}

    if (ret >= 0) {
    	for (unsigned int i = 0; i < tset.count; i++) {
    		auto &row = *tset.pparray[i];
    		const uint64_t mid	= row.get<const uint64_t>(PidTagMid) ? rop_util_get_gc_value(*row.get<const uint64_t>(PidTagMid)) : 0;
    		if (mid == message_id)
    		{

    			exmdbc_read_message_metadata(message_id, &row, msgs_props);
				delete eid;
    			return 0;;
    		}
    	}
    }

    delete eid;
    return -1;
}

int exmdbc_client_mark_message_read(struct exmdb_client *client, const char *username, uint64_t message_id, int mark_as_read, uint64_t *change_number_out)
{
	fprintf(stderr, "[EXMDB] exmdbc_client_mark_message_read called\n");
	if (!client || !username) {
		fprintf(stderr, "[EXMDB] Invalid arguments to mark_message_read\n");
		return -1;
	}

	uint8_t read_flag = mark_as_read ? 1 : 0;
	uint64_t change_number = 0;

	BOOL ok = exmdb_client_remote::set_message_read_state(
		client->dir, username, message_id, read_flag, &change_number);

	if (!ok) {
		fprintf(stderr, "[EXMDB] Failed to mark message as %s\n",
				read_flag ? "read" : "unread");
		return -1;
	}

	if (change_number_out != nullptr)
		*change_number_out = change_number;

	return 0;
}

int exmdbc_client_get_folder_messages(struct exmdb_client *client, uint64_t folder_id,
    struct message_properties *messages, unsigned int max_count,
    const char *username, uint32_t first_uid)
{
	fprintf(stderr, "[EXMDB] exmdbc_client_get_folder_messages called\n");
    if (!client || !messages || !username) {
        fprintf(stderr, "[EXMDBC] Invalid arguments\n");
        return -1;
    }

	STORE_ENTRYID store = {0, 0, 0, 0, {}, 0, deconst(""), deconst("")};
	store.wrapped_provider_uid = g_muidStorePrivate;
	store.pmailbox_dn = deconst(username);
	store.pserver_name = deconst(username);
	char *eid = nullptr;
	unsigned int user_id = 0, domain_id = 0;

	if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
		fprintf(stderr, "[EXMDB] store_eid_to_user failed for user: %s\n", username);
		return -1;
	}

	uint64_t eid_folder = rop_util_make_eid_ex(1, folder_id);

    uint32_t table_id = 0;
    uint32_t row_count = 0;

    if (!exmdb_client_remote::load_content_table(eid, CP_UTF8, eid_folder,
            username, 0, nullptr, nullptr, &table_id, &row_count)) {
        fprintf(stderr, "[EXMDBC] load_content_table failed for folder %" PRIu64 "\n", folder_id);
        return -1;
    }

    if (row_count > max_count)
        row_count = max_count;

    static constexpr gromox::proptag_t required_tags[] = {
        PidTagMid,
        PR_SUBJECT,
        PR_SENDER_NAME,
        PR_DISPLAY_TO,
        PR_BODY,
        PR_CLIENT_SUBMIT_TIME
    };

    PROPTAG_ARRAY tags = {sizeof(required_tags)/sizeof(required_tags[0]), deconst(required_tags)};

    TARRAY_SET tset{};
    if (!exmdb_client_remote::query_table(eid, nullptr, CP_UTF8, table_id,
                                         &tags, 0, row_count, &tset)) {
        fprintf(stderr, "[EXMDBC] query_table failed\n");
        exmdb_client_remote::unload_table(eid, table_id);
        return -1;
    }

    for (unsigned int i = 0; i < tset.count; i++) {
        auto &row = *tset.pparray[i];


    	messages[i].mid	= row.get<const uint64_t>(PidTagMid) ? rop_util_get_gc_value(*row.get<const uint64_t>(PidTagMid)) : 0;
    	const uint32_t* flags_ptr = static_cast<const uint32_t*>(row.getval(PR_MESSAGE_FLAGS));
    	uint32_t flags = (flags_ptr != nullptr) ? *flags_ptr : 0;
    	if (flags & MSGFLAG_UNSENT /* 0x8 */)
    		messages[i].flags += MAIL_DRAFT;
    	if (flags & MSGFLAG_READ /* 0x1 */)
    		messages[i].flags += MAIL_SEEN;

    	const auto flag_status = row.get<const uint32_t>(PR_FLAG_STATUS);
    	if (flag_status != nullptr && *flag_status == followupFlagged /* 0x2 */)
    		messages[i].flags += MAIL_FLAGGED;

    	const auto *icon_index  = row.get<const uint32_t>(PR_ICON_INDEX);
    	if (icon_index != nullptr && *icon_index == MAIL_ICON_REPLIED /* 0x105 */)
    		messages[i].flags += MAIL_ANSWERED;
    }

    exmdb_client_remote::unload_table(eid, table_id);
    return (int)tset.count;
}

int exmdbc_client_set_message_properties(struct exmdb_client *client,
	uint64_t folder_id, uint64_t message_id,
	const char *username, const message_properties *props)
{
	fprintf(stderr, "[EXMDB] exmdbc_client_set_message_properties called\n");
    if (!client || !username || !props) {
        fprintf(stderr, "[EXMDBC] Invalid args\n");
        return -1;
    }

    std::vector<TAGGED_PROPVAL> pv;

	ADD_STR(PR_SENDER_NAME, from_name);
	ADD_STR(PR_SENDER_EMAIL_ADDRESS, from_email);
	ADD_STR(PR_DISPLAY_TO, to_name);
	ADD_STR(PR_EMAIL_ADDRESS, to_email);
	ADD_STR(PR_DISPLAY_CC, cc);
	ADD_STR(PR_DISPLAY_BCC, bcc);
	ADD_STR(PR_SUBJECT, subject);
	ADD_STR(PR_REPLY_RECIPIENT_NAMES, reply_recipment);
	ADD_STR(PR_IN_REPLY_TO_ID, reply_to);
	ADD_STR(PR_INTERNET_MESSAGE_ID, msg_id);

	ADD_STR(PR_TRANSPORT_MESSAGE_HEADERS, message_header);
	ADD_STR(PR_BODY, body_plain);
	ADD_STR(PR_BODY_HTML, body_html);

	ADD_U32(PR_MESSAGE_SIZE, size);
	ADD_FLAGS(PR_MESSAGE_FLAGS, flags);

	ADD_FILETIME(PR_CLIENT_SUBMIT_TIME, submited_time);
	ADD_FILETIME(PR_MESSAGE_DELIVERY_TIME, delivery_time);

    //ADD_U32(PidTagMid, mid);

    TPROPVAL_ARRAY tarr;
    tarr.count = pv.size();
    tarr.ppropval = pv.data();

    BOOL ok = exmdb_client_remote::set_message_properties(
        client->dir, username, CP_UTF8, message_id, &tarr, NULL);

    for (size_t i = 0; i < pv.size(); ++i) {
        if ((pv[i].proptag & 0xFFFF) == PT_UNICODE && pv[i].pvalue)
            free(pv[i].pvalue);
    }

    if (!ok) {
        fprintf(stderr, "[EXMDBC] set_message_properties failed\n");
        return -1;
    }
    return 0;
}

int exmdbc_client_save_message(
    struct exmdb_client *client,
    uint64_t folder_id,
    const char *username,
    const struct message_properties *props,
    uint64_t *outmid)
{
    if (!client || !username || !props) {
        fprintf(stderr, "[EXMDBC] Invalid args for save_message\n");
        return -1;
    }

	std::vector<TAGGED_PROPVAL> pv;


	uint64_t cn = 0;
	if (!exmdb_client_remote::allocate_cn(client->dir, &cn)) {
		fprintf(stderr, "[EXMDBC] allocate_cn failed for user %" PRIu64 "\n", username);
		return -1;
	}
	pv.push_back({PidTagChangeNumber, &cn});

    if (props->from_name)    pv.push_back({PR_SENDER_NAME, (void*)props->from_name});
    if (props->from_email)   pv.push_back({PR_SENDER_EMAIL_ADDRESS, (void*)props->from_email});
    if (props->to_name)      pv.push_back({PR_DISPLAY_TO, (void*)props->to_name});
    if (props->to_email)     pv.push_back({PR_EMAIL_ADDRESS, (void*)props->to_email});
    if (props->cc)           pv.push_back({PR_DISPLAY_CC, (void*)props->cc});
    if (props->bcc)          pv.push_back({PR_DISPLAY_BCC, (void*)props->bcc});
    if (props->subject)      pv.push_back({PR_SUBJECT, (void*)props->subject});
    if (props->reply_recipment) pv.push_back({PR_REPLY_RECIPIENT_NAMES, (void*)props->reply_recipment});
    if (props->reply_to)     pv.push_back({PR_IN_REPLY_TO_ID, (void*)props->reply_to});
    if (props->msg_id)       pv.push_back({PR_INTERNET_MESSAGE_ID, (void*)props->msg_id});
    if (props->message_header) pv.push_back({PR_TRANSPORT_MESSAGE_HEADERS, (void*)props->message_header});


    if (props->body_plain && props->body_size > 0) {
		pv.push_back({PR_BODY, (void*)props->body_plain});
    }
    BINARY html_bin = {0, NULL};
    if (props->body_html && props->body_size > 0) {
        html_bin.cb = (uint32_t)props->body_size;
        html_bin.pc = (char*)props->body_html;
        pv.push_back({ PR_BODY_HTML, &html_bin });
    }

    if (props->flags != 0u) {

    	uint32_t mapi_flags = 0;
    	if (props->flags & MAIL_SEEN)
    		mapi_flags |= MSGFLAG_READ;
    	if (props->flags & MAIL_DRAFT)
    		mapi_flags |= MSGFLAG_UNSENT;

    	pv.push_back({PR_MESSAGE_FLAGS, &mapi_flags});

    	// Flagged (IMAP "Flagged" > MAPI "Flagged")
    	if (props->flags & MAIL_FLAGGED) {
    		static const uint32_t flagged = followupFlagged;
    		pv.push_back({PR_FLAG_STATUS, (void*)&flagged});
    	}

    	// Answered (IMAP "Answered" > MAPI "Replied")
    	if (props->flags & MAIL_ANSWERED) {
    		static const uint32_t replied = MAIL_ICON_REPLIED;
    		pv.push_back({PR_ICON_INDEX, (void*)&replied});
    	}
    }
    if (props->size)               pv.push_back({PR_MESSAGE_SIZE, (void*)&props->size});
    if (props->submited_time) {
        uint64_t ft = unix_time_to_filetime(props->submited_time);
        pv.push_back({PR_CLIENT_SUBMIT_TIME, &ft});
    }
    if (props->delivery_time != 0) {
        uint64_t ft = unix_time_to_filetime(props->delivery_time);
        pv.push_back({PR_MESSAGE_DELIVERY_TIME, &ft});
    }

    TPROPVAL_ARRAY tarr;
    tarr.count = pv.size();
    tarr.ppropval = pv.data();

    MESSAGE_CONTENT msg;
    msg.proplist.count = tarr.count;
    msg.proplist.ppropval = tarr.ppropval;

	ec_error_t e_result;

	uint64_t eid_folder = rop_util_make_eid_ex(1, folder_id);

	uint64_t outcn = 0;
    const BOOL ok = exmdb_client_remote::write_message_v2(
        client->dir,
        CP_UTF8,
        eid_folder,
        &msg,
        outmid,
        &outcn,
        &e_result
    );

    if (ok == FALSE) {
        fprintf(stderr, "[EXMDBC] write_message failed\n");
        return -1;
    }
    return 0;
}

static std::string extract_email_addr(const std::string& field)
{
    auto lt = field.find('<');
    auto gt = field.find('>');
    if (lt != std::string::npos && gt != std::string::npos && gt > lt)
        return field.substr(lt+1, gt-lt-1);
    return field;
}

static std::string extract_display_name(const std::string& field)
{
    auto lt = field.find('<');
    if (lt != std::string::npos)
        return field.substr(0, lt);
    return field;
}

static time_t parse_rfc2822_date(const std::string& val)
{
	struct tm tm = {};
	strptime(val.c_str(), "%a, %d %b %Y %H:%M:%S", &tm);
	time_t t = mktime(&tm);
	return t;
}

bool parse_email(const std::string& raw_email, message_properties& props)
{
    std::istringstream ss(raw_email);
    std::string line;
    std::map<std::string, std::string> headers;
    std::string last_header;
    size_t header_end_pos = 0;

    // 1. Parse headers
    while (std::getline(ss, line)) {
        if (line.empty() || line == "\r") {
            header_end_pos = ss.tellg();
            break;
        }
        if (!last_header.empty() && (line[0] == ' ' || line[0] == '\t')) {
            headers[last_header] += " " + line.substr(1);
            continue;
        }
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            while (!value.empty() && (value[0] == ' ' || value[0] == '\t'))
                value = value.substr(1);
            headers[key] = value;
            last_header = key;
        }
    }

    static std::string s_from_name, s_from_email, s_to_name, s_to_email, s_cc, s_bcc, s_subj, s_msgid, s_reply_to;
    if (headers.count("From")) {
        s_from_email = extract_email_addr(headers["From"]);
        s_from_name = extract_display_name(headers["From"]);
        props.from_email = s_from_email.c_str();
        props.from_name = s_from_name.c_str();
    }
    if (headers.count("To")) {
        s_to_email = extract_email_addr(headers["To"]);
        s_to_name = extract_display_name(headers["To"]);
        props.to_email = s_to_email.c_str();
        props.to_name = s_to_name.c_str();
    }
    if (headers.count("Cc")) {
        s_cc = headers["Cc"];
        props.cc = s_cc.c_str();
    }
    if (headers.count("Bcc")) {
        s_bcc = headers["Bcc"];
        props.bcc = s_bcc.c_str();
    }
    if (headers.count("Subject")) {
        s_subj = headers["Subject"];
        props.subject = s_subj.c_str();
    }
    if (headers.count("Message-ID")) {
        s_msgid = headers["Message-ID"];
        props.msg_id = s_msgid.c_str();
    }
    if (headers.count("Reply-To")) {
        s_reply_to = headers["Reply-To"];
        props.reply_to = s_reply_to.c_str();
    }
    if (headers.count("Date")) {
        props.submited_time = parse_rfc2822_date(headers["Date"]);
    }
    // TODO: delivery_time (Received/Delivered-To)

    // Header blob
    static std::string s_header_blob;
    s_header_blob = raw_email.substr(0, header_end_pos);
    props.message_header = s_header_blob.c_str();

    // 3. Body (plain + html)
    std::string body = raw_email.substr(header_end_pos);
    size_t html_start = body.find("<html");
    size_t plain_start = 0;
    static std::string s_body_html, s_body_plain;
    if (html_start != std::string::npos) {
        s_body_html = body.substr(html_start);
        props.body_html = s_body_html.c_str();
        if (html_start > 0)
            s_body_plain = body.substr(plain_start, html_start - plain_start);
        else
            s_body_plain = "";
        props.body_plain = s_body_plain.c_str();
        props.body_size = (uint32_t)s_body_plain.size();
    } else {
        s_body_plain = body;
        props.body_plain = s_body_plain.c_str();
        props.body_size = (uint32_t)s_body_plain.size();
    }

	props.size = (uint32_t)raw_email.size();
    return true;
}

int exmdbc_client_save_body(struct exmdb_client *client, uint64_t folder_id, const char *username, const void *body,
size_t body_len, uint64_t *out_mid, uint32_t imap_flags)
{
	struct message_properties props = {0};
	std::string raw_email((const char*)body, body_len);
	if (!parse_email(raw_email, props)) {
		return -1;
	}

	if (imap_flags != 0)
		props.flags = imap_flags;

	return exmdbc_client_save_message(client, folder_id, username, &props, out_mid);
}

int exmdbc_client_copy_message(struct exmdb_client *client, uint64_t src_message_id, uint64_t dst_folder_id,
	const char *username)
{
	fprintf(stderr, "[EXMDB] exmdbc_client_copy_message called\n");
	if (!client || !username) {
		fprintf(stderr, "[EXMDB] Invalid arguments in copy_message\n");
		return -1;
	}

	STORE_ENTRYID store = {0, 0, 0, 0, {}, 0, deconst(""), deconst("")};
	store.wrapped_provider_uid = g_muidStorePrivate;
	store.pmailbox_dn = deconst(username);
	store.pserver_name = deconst(username);

	char *eid = nullptr;
	unsigned int user_id = 0, domain_id = 0;

	if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
		fprintf(stderr, "[EXMDB] store_eid_to_user failed in copy_message for user: %s\n", username);
		return -1;
	}

	uint64_t dst_fid = rop_util_make_eid_ex(1, dst_folder_id);
	uint64_t dst_id = 0;
	BOOL b_move = FALSE;
	BOOL pb_result = FALSE;

	BOOL ok = exmdb_client_remote::movecopy_message(
		eid,
		CP_UTF8,
		src_message_id, //MID
		dst_fid,
		dst_id,
		b_move, //COPY
		&pb_result
	);

	if (!ok || !pb_result) {
		fprintf(stderr, "[EXMDB] movecopy_message RPC failed (ok=%d, pb_result=%d)\n", ok, pb_result);
		delete eid;
		return -1;
	}

	delete eid;
	return 0;
}
static const RESTRICTION*
build_restriction(const exmdbc_search_spec *spec,
                  std::vector<SRestriction>         &nodes,
                  std::vector<SPropertyRestriction> &props,
                  std::vector<SBitMaskRestriction>  &bmsk,
                  std::vector<SContentRestriction>  &cont,
                  restriction_list                  &root_and)
{
    nodes.clear(); props.clear(); bmsk.clear(); cont.clear();
    if (!spec) return nullptr;

    auto push_prop = [&](const SPropertyRestriction &pr){
        props.push_back(pr);
        SRestriction r{}; r.rt = RES_PROPERTY; r.prop = &props.back();
        nodes.push_back(r);
    };
    auto push_bm = [&](const SBitMaskRestriction &bm) {
        bmsk.push_back(bm);
        SRestriction r{}; r.rt = RES_BITMASK; r.bm = &bmsk.back();
        nodes.push_back(r);
    };
    auto push_cont = [&](const SContentRestriction &cr) {
        cont.push_back(cr);
        SRestriction r{}; r.rt = RES_CONTENT; r.cont = &cont.back();
        nodes.push_back(r);
    };

    //SEEN/UNSEEN - PR_MESSAGE_FLAGS bitmask
    constexpr uint32_t MSGFLAG_READ = 0x0001;
    if (spec->want_unseen && !spec->want_seen) {
        SBitMaskRestriction bm{ BMR_EQZ, PR_MESSAGE_FLAGS, MSGFLAG_READ };
        push_bm(bm);
    } else if (spec->want_seen && !spec->want_unseen) {
        SBitMaskRestriction bm{ BMR_NEZ, PR_MESSAGE_FLAGS, MSGFLAG_READ };
        push_bm(bm);
    }

    //UID range via PidTagMid GE/LE
    if (spec->uid_lo || spec->uid_hi) {
        auto lo = (std::uint64_t)(spec->uid_lo ? spec->uid_lo : 0);
        auto hi = (std::uint64_t)(spec->uid_hi ? spec->uid_hi : 0xFFFFFFFFULL);

        SPropertyRestriction ge{};
        ge.relop   = RELOP_GE;
        ge.proptag = PidTagMid;
        ge.propval.proptag = CHANGE_PROP_TYPE(PidTagMid, PT_I8);
        ge.propval.pvalue  = &lo;

        SPropertyRestriction le{};
        le.relop   = RELOP_LE;
        le.proptag = PidTagMid;
        le.propval.proptag = CHANGE_PROP_TYPE(PidTagMid, PT_I8);
        le.propval.pvalue  = &hi;

        props.push_back(ge); props.back().propval.pvalue = &((SPropertyRestriction&)props.back()).propval;
        props.back().propval.pvalue = &lo;
        SRestriction r1{}; r1.rt = RES_PROPERTY; r1.prop = &props.back(); nodes.push_back(r1);

        props.push_back(le); props.back().propval.pvalue = &hi;
        SRestriction r2{}; r2.rt = RES_PROPERTY; r2.prop = &props.back(); nodes.push_back(r2);
    }

    //Dates on PR_MESSAGE_DELIVERY_TIME (SINCE >=, BEFORE <)
    gromox::mapitime_t ft_since=0, ft_before=0;
    if (spec->since_utc) {
        ft_since = unix_time_to_filetime(spec->since_utc);
        SPropertyRestriction pr{};
        pr.relop = RELOP_GE; pr.proptag = PR_MESSAGE_DELIVERY_TIME;
        pr.propval.proptag = CHANGE_PROP_TYPE(PR_MESSAGE_DELIVERY_TIME, PT_SYSTIME);
        pr.propval.pvalue  = &ft_since;
        push_prop(pr);
    }
    if (spec->before_utc) {
        ft_before = unix_time_to_filetime(spec->before_utc);
        SPropertyRestriction pr{};
        pr.relop = RELOP_LT; pr.proptag = PR_MESSAGE_DELIVERY_TIME;
        pr.propval.proptag = CHANGE_PROP_TYPE(PR_MESSAGE_DELIVERY_TIME, PT_SYSTIME);
        pr.propval.pvalue  = &ft_before;
        push_prop(pr);
    }

    //Headers contains
    auto add_contains = [&](gromox::proptag_t tag, const char *s){
        if (!s || !*s) return;
        SContentRestriction cr{};
        cr.fuzzy_level = FL_SUBSTRING | FL_IGNORECASE;
        cr.proptag = tag;
        cr.propval.proptag = CHANGE_PROP_TYPE(tag, PT_UNICODE);
        cr.propval.pvalue  = (void*)s;
        push_cont(cr);
    };
    add_contains(PR_SUBJECT,     spec->subject);
    add_contains(PR_SENDER_NAME, spec->from_);
    add_contains(PR_DISPLAY_TO,  spec->to_);
    add_contains(PR_DISPLAY_CC,  spec->cc);

    //Size filters
    std::uint32_t v_smaller=0, v_larger=0;
    if (spec->smaller_than) {
        v_smaller = spec->smaller_than;
        SPropertyRestriction pr{};
        pr.relop = RELOP_LT; pr.proptag = PR_MESSAGE_SIZE;
        pr.propval.proptag = CHANGE_PROP_TYPE(PR_MESSAGE_SIZE, PT_LONG);
        pr.propval.pvalue  = &v_smaller;
        push_prop(pr);
    }
    if (spec->larger_than) {
        v_larger = spec->larger_than;
        SPropertyRestriction pr{};
        pr.relop = RELOP_GT; pr.proptag = PR_MESSAGE_SIZE;
        pr.propval.proptag = CHANGE_PROP_TYPE(PR_MESSAGE_SIZE, PT_LONG);
        pr.propval.pvalue  = &v_larger;
        push_prop(pr);
    }

    if (nodes.empty()) return nullptr; //All

    root_and.count = (uint32_t)nodes.size();
    root_and.pres  = nodes.data();

    static SRestriction root;
    root.rt = RES_AND;
    root.andor = &root_and;
    return &root;
}

int exmdbc_client_search_uids(struct exmdb_client *client,
                           uint64_t folder_id,
                           const char *username,
                           struct exmdbc_search_spec *spec,
                           uint32_t **uids_r, unsigned *count_r)
{
    if (!client || !username || !uids_r || !count_r) return -1;
    *uids_r = nullptr; *count_r = 0;

    STORE_ENTRYID store{0,0,0,0,{},0, deconst(username), deconst(username)};
    store.wrapped_provider_uid = g_muidStorePrivate;

    char *eid = nullptr; unsigned user_id=0, domain_id=0;
    if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id))
        return -1;

    const std::uint64_t eid_folder = rop_util_make_eid_ex(1, folder_id);

    std::vector<SRestriction>         nodes; nodes.reserve(16);
    std::vector<SPropertyRestriction> props; props.reserve(16);
    std::vector<SBitMaskRestriction>  bmsk;  bmsk.reserve(4);
    std::vector<SContentRestriction>  cont;  cont.reserve(8);
    restriction_list root_and{};

    const RESTRICTION *prestr = build_restriction(spec, nodes, props, bmsk, cont, root_and);

    const SORTORDER_SET *psorts = nullptr; // TODO: map IMAP SORT if needed

    uint32_t table_id = 0, row_count = 0;
    if (!exmdb_client_remote::load_content_table(eid, CP_UTF8, eid_folder, username, 0, prestr, psorts, &table_id, &row_count))
        return -1;

    static constexpr gromox::proptag_t cols[] = { PidTagMid };
    PROPTAG_ARRAY tags{ std::size(cols), deconst(cols) };

    TARRAY_SET tset{};
    if (!exmdb_client_remote::query_table(eid, username, CP_UTF8, table_id,
            &tags, 0, row_count, &tset)) {
        exmdb_client_remote::unload_table(eid, table_id);
        return -1;
    }

    const auto out = static_cast<std::uint32_t *>(std::malloc(sizeof(std::uint32_t) * tset.count));
    if (!out) { exmdb_client_remote::unload_table(eid, table_id); return -1; }

    unsigned n = 0;
    for (uint32_t i = 0; i < tset.count; ++i) {
        const auto &row = *tset.pparray[i];
        const std::uint64_t *mid64 = row.get<const std::uint64_t>(PidTagMid);
        std::uint32_t uid = mid64 ? (std::uint32_t)rop_util_get_gc_value(*mid64) : 0;
        if (uid != 0) out[n++] = uid;
    }

    exmdb_client_remote::unload_table(eid, table_id);
    *uids_r = out; *count_r = n;
    return (int)n;
}

}