#include "exmdb_client_c.h"

#include <libHX/scope.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include <gromox/util.hpp>


using gromox::exmdb_client_remote;

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

int exmdbc_client_ping_store(struct exmdb_client *client, const char *dir)
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

int exmdbc_client_get_folder_dtos(struct exmdb_client *client,
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
	// store.version = 1;
	store.wrapped_provider_uid = g_muidStorePrivate;
	// store.pserver_name = deconst("");
	store.pmailbox_dn = deconst(username);
	store.pserver_name = deconst(username);
	char *eid = nullptr;
	unsigned int user_id = 0, domain_id = 0;
	const char *gromox_http_url = "http://[::1]:5000/";

	fprintf(stderr, "[EXMDB] Resolving EID for user: %s\n", username);
	if (!exmdb_client_remote::store_eid_to_user(client->dir, &store, &eid, &user_id, &domain_id)) {
		fprintf(stderr, "[EXMDB] store_eid_to_user failed for user: %s\n", username);
		return -1;
	}

	fprintf(stderr, "[EXMDB] store_eid_to_user -> eid=%s\n", eid);

	FOLDER_CHANGES fldchgs = {};
	uint64_t last_cn = 0;
	EID_ARRAY given_fids = {};
	EID_ARRAY deleted_fids = {};
	auto empty_idset = idset::create(idset::type::id_packed);

	BOOL ret = exmdb_client_remote::get_hierarchy_sync(eid,
														PRIVATE_FID_ROOT,
														username,
														empty_idset.get(),   // pgiven
														nullptr,             // pseen
														&fldchgs,
														&last_cn,
														&given_fids,
														&deleted_fids
													);
	if (ret < 0) {
		fprintf(stderr, "[EXMDB] get_hierarchy_sync failed for eid=%s\n", eid);
		free(eid);
		return -1;
	}
	if (fldchgs.pfldchgs == nullptr || fldchgs.count == 0) {
		fprintf(stderr, "[EXMDBC] No folders found — attempting to create INBOX\n");
		TPROPVAL_ARRAY props = {};
		TAGGED_PROPVAL vals[2];
		props.count = 0;
		props.ppropval = vals;
		eid_t parent_eid = (1ULL << 48) | (PRIVATE_FID_ROOT & 0xFFFFFFFFFFFFULL);
		props.emplace_back(PidTagParentFolderId, &parent_eid);
		const char *folder_name = "INBOX";
		props.emplace_back(PR_DISPLAY_NAME, folder_name);
		uint64_t cn = 0;
		props.emplace_back(PidTagChangeNumber, &cn);
		uint8_t pcl_data[1] = {0};
		props.emplace_back(PR_PREDECESSOR_CHANGE_LIST, pcl_data);

		unsigned long new_folder_id = 0;

		int create_rc = exmdbc_client_create_folder_v1(
			client,
			eid,
			1,
			&props,
			&new_folder_id
		);

		if (create_rc != 0) {
			fprintf(stderr, "[EXMDBC] Failed to create INBOX: %s\n", strerror(-create_rc));
			return -1;
		}

		fprintf(stderr, "[EXMDBC] INBOX created with folder_id = %lu\n", new_folder_id);

		memset(&fldchgs, 0, sizeof(FOLDER_CHANGES));
		last_cn = 0;
		given_fids = {};
		deleted_fids = {};

		ret = exmdb_client_remote::get_hierarchy_sync(eid,
													PRIVATE_FID_ROOT,
													username,
													empty_idset.get(),   // pgiven
													nullptr,             // pseen
													&fldchgs,
													&last_cn,
													&given_fids,
													&deleted_fids
												);

		if (ret < 0 || fldchgs.count == 0 || fldchgs.pfldchgs == nullptr) {
			fprintf(stderr, "[EXMDBC] Still no folders after creation — error\n");
			return -1;
		}
	}

	for (uint32_t i = 0; i < fldchgs.count && *out_count < max_count; ++i) {
		const TPROPVAL_ARRAY &row = fldchgs.pfldchgs[i];
		const char *name = *row.get<const char *>(0x3001001F); // PR_DISPLAY_NAME
		if (name == nullptr)
			continue;

		struct exmdbc_folder_dto &dto = out_array[(*out_count)++];
		dto.name = name;
		dto.flags = 0; // MAILBOX_NOSELECT;
	}

	// Free memory
	free(eid);
	//heap_free(fldchgs.pfldchgs);

	return 0;
}

void exmdb_client_set_dir(struct exmdb_client *client, const char *dir)
{
	if (client != nullptr) {
		client->dir = dir != nullptr ? strdup(dir) : nullptr;
	}
}

}


