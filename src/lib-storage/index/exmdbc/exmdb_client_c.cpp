#include "exmdb_client_c.h"

#include <inttypes.h>
#include <libHX/scope.hpp>
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

using gromox::exmdb_client_remote;

using LLU = unsigned long long;

extern "C" {

struct exmdb_client {
	exmdb_client_remote *impl;
	const char *dir;
};

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
		free(eid);
		return -1;
	}

	static constexpr uint32_t ftags[] = {PidTagFolderId, PR_DISPLAY_NAME, PR_FOLDER_PATHNAME};
	static constexpr PROPTAG_ARRAY ftaghdr = {std::size(ftags), deconst(ftags)};
	tarray_set rowset{};
	if (!exmdb_client_remote::query_table(eid, nullptr, CP_ACP, table_id,
		&ftaghdr, 0, row_count, &rowset)) {
		fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
		}
	exmdb_client_remote::unload_table(eid, table_id);
	for (const auto &row : rowset) {
		auto name = row.get<const char>(PR_DISPLAY_NAME);
		auto pathname = row.get<const char>(PR_FOLDER_PATHNAME);
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
	free(eid);

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
	if (!exmdb_client_remote::get_folder_properties(eid, CP_ACP, eid_folder, &ftaghdr2, &props)) {
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
	free(eid);
	return 0;
}

void exmdb_client_set_dir(struct exmdb_client *client, const char *dir)
{
	if (client != nullptr) {
		client->dir = dir != nullptr ? strdup(dir) : nullptr;
	}
}


int exmdbc_read_message_metadata(const char *dir, const char *username, uint64_t mid, struct folder_metadata_message *out)
{
	MESSAGE_CONTENT *msg = nullptr;
	// cpid_t cpid = static_cast<cpid_t>(_cpid); //TODO:EXMDB

	cpid_t cpid = CP_UTF8;
	if (!exmdb_client_remote::read_message(dir, username, cpid, mid, &msg))
		return -1;

	TPROPVAL_ARRAY *props = msg->get_proplist();

	out->mid = mid;

	out->subject    = static_cast<const char *>(props->getval(PR_SUBJECT_A));
	out->from       = static_cast<const char *>(props->getval(PR_SENDER_EMAIL_ADDRESS_A));
	out->to         = static_cast<const char *>(props->getval(PR_DISPLAY_TO_A));
	out->body_plain = static_cast<const char *>(props->getval(PR_BODY_A));
	out->body_html  = static_cast<const char *>(props->getval(PR_BODY_HTML_A));

	const void *val = props->getval(PR_CLIENT_SUBMIT_TIME);
	out->timestamp = val ? *reinterpret_cast<const uint64_t *>(val) : 0;

	exmdb_rpc_free(msg); // TODO:EXMDBC: ask Jan if this call is correct

	return 0;
}

int exmdbc_client_get_message_dtos(struct exmdb_client *client, uint64_t folder_id,
                                   struct folder_metadata_message *messages,
                                   unsigned int max_messages, const char *username)
{
    if (!client || !username || !messages) {
        fprintf(stderr, "[EXMDB] Invalid arguments to get_message_dtos\n");
        return -1;
    }

    STORE_ENTRYID store = {0, 0, 0, 0, {}, 0, deconst(""), deconst("")};
    store.wrapped_provider_uid = g_muidStorePrivate;
    store.pmailbox_dn = deconst(username);
    store.pserver_name = deconst(username);

    char *eid = nullptr;
    unsigned int user_id = 0, domain_id = 0;

    if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
        fprintf(stderr, "[EXMDB] Failed to resolve EID\n");
        return -1;
    }

    uint32_t table_id = 0, row_count = 0;
    BOOL ok = exmdb_client_remote::load_content_table(
        client->dir, CP_ACP, folder_id, username, 0, nullptr, nullptr, &table_id, &row_count);
    if (!ok || row_count == 0) {
        fprintf(stderr, "[EXMDB] Failed to load content table for folder 0x%llx\n", LLU{folder_id});
        free(eid);
        return -1;
    }

    static constexpr uint32_t tags[] = {
        PR_ENTRYID,
        PR_SUBJECT_A,
        PR_SENDER_NAME_A,
        PR_DISPLAY_TO_A,
        PR_BODY_A,
        PR_BODY_HTML_A,
        PR_CLIENT_SUBMIT_TIME,
    	PR_MESSAGE_FLAGS,
    	PR_FLAG_STATUS,
    	PR_ICON_INDEX,
    	PR_MESSAGE_SIZE
    };
    static constexpr PROPTAG_ARRAY ptag_array = { std::size(tags), deconst(tags) };

    tarray_set rowset = {};
    if (!exmdb_client_remote::query_table(eid, nullptr, CP_ACP, table_id, &ptag_array, 0, max_messages, &rowset)) {
        fprintf(stderr, "[EXMDB] query_table failed\n");
        exmdb_client_remote::unload_table(eid, table_id);
        free(eid);
        return -1;
    }

    exmdb_client_remote::unload_table(eid, table_id);
    free(eid);

    size_t i = 0;
    for (const TPROPVAL_ARRAY &props : rowset) {
        if (i >= max_messages)
            break;

        folder_metadata_message &msg = messages[i];
        msg.mid = props.get<uint64_t>(PR_ENTRYID) ? *props.get<uint64_t>(PR_ENTRYID) : 0;
        msg.subject = static_cast<const char *>(props.getval(PR_SUBJECT_A));
        msg.from = static_cast<const char *>(props.getval(PR_SENDER_NAME_A));
        msg.to = static_cast<const char *>(props.getval(PR_DISPLAY_TO_A));
        msg.body_plain = static_cast<const char *>(props.getval(PR_BODY_A));
        msg.body_html = static_cast<const char *>(props.getval(PR_BODY_HTML_A));


    	const void *val = props.getval(PR_CLIENT_SUBMIT_TIME);
    	msg.timestamp = val ? *reinterpret_cast<const uint64_t *>(val) : 0;

        ++i;
    }

    return static_cast<int>(i);
}
int exmdbc_client_get_message_properties(struct exmdb_client *client, uint64_t message_id, const char *username, struct property_metadata *meta_out)
{
	if (!client || !username || !meta_out) {
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

	static const uint32_t tags[] = {
		PR_ENTRYID,
		PR_SUBJECT_A,
		PR_SENDER_NAME_A,
		PR_DISPLAY_TO_A,
		PR_BODY_A,
		PR_BODY_HTML_A,
		PR_CLIENT_SUBMIT_TIME,
		PR_MESSAGE_FLAGS,
		PR_FLAG_STATUS,
		PR_ICON_INDEX,
		PR_MESSAGE_SIZE
	};
	PROPTAG_ARRAY tag_array = {
		(uint16_t)(sizeof(tags) / sizeof(tags[0])),
		deconst(tags)
	};

	TPROPVAL_ARRAY out_props{};
	BOOL ok = exmdb_client_remote::get_message_properties(
		client->dir, username, CP_ACP, message_id, &tag_array, &out_props);
	free(eid);
	if (!ok) return -1;

	meta_out->mid        = message_id;
	meta_out->subject    = static_cast<const char *>(out_props.getval(PR_SUBJECT_A));
	meta_out->from       = static_cast<const char *>(out_props.getval(PR_SENDER_NAME_A));
	meta_out->to         = static_cast<const char *>(out_props.getval(PR_DISPLAY_TO_A));
	meta_out->body_plain = static_cast<const char *>(out_props.getval(PR_BODY_A));
	meta_out->body_html  = static_cast<const char *>(out_props.getval(PR_BODY_HTML_A));

	const void *val = out_props.getval(PR_CLIENT_SUBMIT_TIME);
	meta_out->timestamp = val != nullptr ? *static_cast<const uint64_t *>(val) : 0;

	const uint32_t* flags_ptr = static_cast<const uint32_t*>(out_props.getval(PR_MESSAGE_FLAGS));
	uint32_t flags = (flags_ptr != nullptr) ? *flags_ptr : 0;
	if (flags & MSGFLAG_UNSENT /* 0x8 */)
		meta_out->flags += MAIL_DRAFT;
	if (flags & MSGFLAG_READ /* 0x1 */)
		meta_out->flags += MAIL_SEEN;

	const auto flag_status = out_props.get<const uint32_t>(PR_FLAG_STATUS);
	if (flag_status != nullptr && *flag_status == followupFlagged /* 0x2 */)
		meta_out->flags += MAIL_FLAGGED;

	const auto *icon_index  = out_props.get<const uint32_t>(PR_ICON_INDEX);
	if (icon_index != nullptr && *icon_index == MAIL_ICON_REPLIED /* 0x105 */)
		meta_out->flags += MAIL_ANSWERED;

	//TODO:EMXDBC: Not found analogue. Need to investigate more
	// if (icon_index != nullptr && *icon_index == MAIL_ICON_FORWARDED /* 0x106 */)
	// 	meta_out->flags += "\\Forwarded";

	// There is Deleted in IMAP\Dovecot but not in MAPI so i skipping it for reading and when writing i will need to delete it before saving. (Need to discuss with Jan)

	return 0;
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
    struct folder_metadata_message *messages, unsigned int max_count,
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

    if (!exmdb_client_remote::load_content_table(eid, CP_ACP, eid_folder,
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
    if (!exmdb_client_remote::query_table(eid, nullptr, CP_ACP, table_id,
                                         &tags, 0, row_count, &tset)) {
        fprintf(stderr, "[EXMDBC] query_table failed\n");
        exmdb_client_remote::unload_table(eid, table_id);
        return -1;
    }

    for (unsigned int i = 0; i < tset.count; i++) {
        auto &row = *tset.pparray[i];
        messages[i].mid = row.get<const uint64_t>(PidTagMid) ? rop_util_get_gc_value(*row.get<const uint64_t>(PidTagMid)) : 0;

        const char *subject = row.get<const char>(PR_SUBJECT);
        messages[i].subject = subject ? strdup(subject) : nullptr;

        const char *from = row.get<const char>(PR_SENDER_NAME);
        messages[i].from = from ? strdup(from) : nullptr;

        const char *to = row.get<const char>(PR_DISPLAY_TO);
        messages[i].to = to ? strdup(to) : nullptr;

        const char *body_html = row.get<const char>(PR_BODY_HTML);
        const char *body_plain = row.get<const char>(PR_BODY);

        messages[i].body_html = body_html ? strdup(body_html) : nullptr;
        messages[i].body_plain = (!body_html && body_plain) ? strdup(body_plain) : nullptr;

        auto ts_ptr = row.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
        messages[i].timestamp = ts_ptr ? *ts_ptr : 0;

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


}