#include "exmdb_client_c.h"

#include <iconv.h>
#include <inttypes.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#include <gromox/rop_util.hpp>

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
	fprintf(stdout, "[EXMDB] exmdbc_client_ping_store client is local\n");
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
	fprintf(stdout, "[EXMDBC] exmdbc_client_ping_store client is remote\n");
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

	fprintf(stderr, "[EXMDB] Resolving EID for user: %s\n", username);
	if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
		fprintf(stderr, "[EXMDB] store_eid_to_user failed for user: %s\n", username);
		return -1;
	}

	fprintf(stderr, "[EXMDB] store_eid_to_user -> eid=%s\n", eid);
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

		fprintf(stderr, "[EXMDB] folder name: %s,  folder pathname: %s\n", name, pathname);

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

	fprintf(stderr, "[EXMDB] Resolving EID for user: %s\n", username);
	if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
		fprintf(stderr, "[EXMDB] store_eid_to_user failed for user: %s\n", username);
		return -1;
	}

	fprintf(stderr, "[EXMDB] store_eid_to_user -> eid=%s\n", eid);


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

	msgs_props->body_plain = static_cast<const char *>(props->getval( PR_BODY_A));
	msgs_props->body_html  = static_cast<const char *>(props->getval( PR_BODY_HTML));
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

	//TODO:EMXDBC: Not found analogue. Need to investigate more
	// if (icon_index != nullptr && *icon_index == MAIL_ICON_FORWARDED /* 0x106 */)
	// 	msgs_props->flags += "\\Forwarded";

	// There is Deleted in IMAP\Dovecot but not in MAPI so i skipping it for reading and when writing i will need to delete it before saving. (Need to discuss with Jan)


	return 0;
}

int exmdbc_client_get_message_properties(struct exmdb_client *client, uint64_t folder_id, uint64_t message_id, const char *username, struct message_properties *msgs_props) {
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

	uint32_t table_id = 0;
	uint32_t row_count = 0;

	if (!exmdb_client_remote::load_content_table(eid, CP_UTF8, eid_folder,
			username, 0, nullptr, nullptr, &table_id, &row_count)) {
		fprintf(stderr, "[EXMDBC] load_content_table failed for folder %" PRIu64 "\n", folder_id);
		return -1;
			}

	static const uint32_t tags[] = {
		PidTagMid,
		PR_ENTRYID,
		PR_SENDER_NAME,
		PR_SENDER_EMAIL_ADDRESS,
		PR_DISPLAY_TO,
		PR_EMAIL_ADDRESS,
		PR_DISPLAY_CC,
		PR_DISPLAY_BCC,
		PR_SUBJECT,
		PR_REPLY_RECIPIENT_NAMES,
		PR_IN_REPLY_TO_ID,
		PR_INTERNET_MESSAGE_ID,
		PR_TRANSPORT_MESSAGE_HEADERS,
		PR_BODY,
		PR_BODY_HTML,
		PR_MESSAGE_SIZE,
		PR_CLIENT_SUBMIT_TIME,
		PR_MESSAGE_DELIVERY_TIME,
		PR_MESSAGE_FLAGS,
		PR_FLAG_STATUS,
		PR_ICON_INDEX
	};
	PROPTAG_ARRAY tag_array = {
		(uint16_t)(sizeof(tags) / sizeof(tags[0])),
		deconst(tags)
	};

	if (false) {
		TARRAY_SET tset{};
		if (!exmdb_client_remote::query_table(eid, nullptr, CP_UTF8, table_id,
											 &tag_array, 0, row_count, &tset)) {
			fprintf(stderr, "[EXMDBC] query_table failed\n");
			exmdb_client_remote::unload_table(eid, table_id);
			return -1;
											 }

		for (unsigned int i = 0; i < tset.count; i++) {
			auto &row = *tset.pparray[i];
			const uint64_t mid	= row.get<const uint64_t>(PidTagMid) ? rop_util_get_gc_value(*row.get<const uint64_t>(PidTagMid)) : 0;
			if (mid == message_id)
			{

				exmdbc_read_message_metadata(message_id, &row, msgs_props);
				return 0;
			}
		}
		return -1;
	}
	else
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
}

int exmdbc_client_mark_message_read(struct exmdb_client *client, const char *username, uint64_t message_id, int mark_as_read, uint64_t *change_number_out)
{
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

	fprintf(stderr, "[EXMDB] Resolving EID for user: %s\n", username);
	if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
		fprintf(stderr, "[EXMDB] store_eid_to_user failed for user: %s\n", username);
		return -1;
	}

	fprintf(stderr, "[EXMDB] store_eid_to_user -> eid=%s\n", eid);


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
        PR_BODY_HTML,
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

    	//TODO:EMXDBC: Not found analogue. Need to investigate more
    	// if (icon_index != nullptr && *icon_index == MAIL_ICON_FORWARDED /* 0x106 */)
    	// 	messages[i].flags += "\\Forwarded";

    	// There is Deleted in IMAP\Dovecot but not in MAPI so i skipping it for reading and when writing i will need to delete it before saving. (Need to discuss with Jan)
    }

    exmdb_client_remote::unload_table(eid, table_id);
    return (int)tset.count;
}

int exmdbc_client_set_message_properties(struct exmdb_client *client,
	uint64_t folder_id, uint64_t message_id,
	const char *username, const message_properties *props)
{
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
    const struct message_properties *props)
{
    if (!client || !username || !props) {
        fprintf(stderr, "[EXMDBC] Invalid args for save_message\n");
        return -1;
    }

	std::vector<TAGGED_PROPVAL> pv;

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


    BINARY body_bin = {0, NULL};
    if (props->body_plain && props->body_size > 0) {
        body_bin.cb = (uint32_t)props->body_size;
        body_bin.pc = (char*)props->body_plain;
        pv.push_back({ PR_BODY, &body_bin });
    }
    BINARY html_bin = {0, NULL};
    if (props->body_html && props->body_size > 0) {
        html_bin.cb = (uint32_t)props->body_size;
        html_bin.pc = (char*)props->body_html;
        pv.push_back({ PR_BODY_HTML, &html_bin });
    }

    if (props->flags != 0u)        pv.push_back({PR_MESSAGE_FLAGS, (void*)&props->flags});
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

    const BOOL ok = exmdb_client_remote::write_message(
        client->dir,
        CP_UTF8,
        folder_id,
        &msg,
        nullptr
    );

    if (ok == FALSE) {
        fprintf(stderr, "[EXMDBC] write_message failed\n");
        return -1;
    }
    return 0;
}

int exmdbc_client_save_body(struct exmdb_client *client, uint64_t folder_id, const char *username, const void *body,
	size_t body_len)
{
	struct message_properties props = {0};
	props.body_plain = (const char*)body;
	props.body_size = (uint32_t)body_len;

	return exmdbc_client_save_message(client, folder_id, username, &props);
}


}

