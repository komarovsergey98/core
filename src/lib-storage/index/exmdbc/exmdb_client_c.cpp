#include "exmdb_client_c.h"

#include <libHX/scope.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#include <gromox/rop_util.hpp>


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

	FOLDER_CHANGES fldchgs = {};
	uint64_t last_cn = 0;
	uint64_t fid = 0;
	EID_ARRAY given_fids = {};
	EID_ARRAY deleted_fids = {};
	auto empty_idset = idset::create(idset::type::id_packed);

	uint32_t table_id = 0, row_count = 0;
	fid = rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE);
	BOOL ret = exmdb_client_remote::load_hierarchy_table(eid, eid_folder, nullptr, 0, nullptr, &table_id, &row_count);
	if (ret != TRUE) {
		fprintf(stderr, "[EXMDB] query_table failed for folder_id=0x%llx\n", LLU{folder_id});
		free(eid);
		return -1;
	}

	static constexpr uint32_t ftags[] = {
		PR_CONTENT_COUNT,       // uint32_t
		PR_CHANGE_KEY           // MODSEQ (optional)
	};

	static constexpr PROPTAG_ARRAY ftaghdr = {std::size(ftags), deconst(ftags)};
	tarray_set rowset{};
	if (!exmdb_client_remote::query_table(eid, nullptr, CP_ACP, table_id,
		&ftaghdr, 0, row_count, &rowset)) {
		fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
		}
	exmdb_client_remote::unload_table(eid, table_id);

	if (rowset.count == 0 || rowset.begin() == rowset.end()) {
		fprintf(stderr, "[EXMDB] No metadata row found for folder_id=0x%llx\n", LLU{folder_id});
		free(eid);
		return -1;
	}

	const TPROPVAL_ARRAY &props = *rowset.begin();

	auto pnum = props.get<uint32_t>(PR_CONTENT_COUNT);
	auto pmodseq = props.get<uint64_t>(PR_CHANGE_KEY);


	folder_metadata->num_messages = pnum ? *pnum : 0;
	folder_metadata->modseq = pmodseq ? *pmodseq : 1;
	folder_metadata->uidvalidity = 1;
	folder_metadata->uidnext = 1;

	// Free memory
	free(eid);
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
        PR_CLIENT_SUBMIT_TIME
    };

	//TODO:EXMDBC : add PR_MESSAGE_FLAGS, PR_INTERNAL_DATE, PR_MESSAGE_SIZE
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
	meta_out->subject    = (const char *)out_props.getval(PR_SUBJECT_A);
	meta_out->from       = (const char *)out_props.getval(PR_SENDER_NAME_A);
	meta_out->to         = (const char *)out_props.getval(PR_DISPLAY_TO_A);
	meta_out->body_plain = (const char *)out_props.getval(PR_BODY_A);
	meta_out->body_html  = (const char *)out_props.getval(PR_BODY_HTML_A);

	const void *val = out_props.getval(PR_CLIENT_SUBMIT_TIME);
	meta_out->timestamp = val ? *reinterpret_cast<const uint64_t *>(val) : 0;

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

}

