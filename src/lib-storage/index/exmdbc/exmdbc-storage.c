#include "lib.h"
#include "ioloop.h"
#include "mailbox-list-private.h"
#include "exmdbc-storage.h"
#include <stdio.h>

#include <exmdb_client_c.h>
#include <hash.h>

#include "exmdbc-mailbox.h"
#include "exmdbc-attribute.h"
#include "exmdbc-sync.h"

extern struct mailbox exmdbc_mailbox;

static struct mail_storage *exmdbc_storage_alloc(void)
{
	fprintf(stdout, "!!! exmdbc_storage_alloc called\n");
	pool_t pool = pool_alloconly_create("exmdbc storage", 2048);
	struct exmdbc_storage *storage = p_new(pool, struct exmdbc_storage, 1);
	storage->storage = exmdbc_storage;
	storage->storage.pool = pool;
	storage->root_ioloop = current_ioloop;
	return &storage->storage;
}

struct exmdb_client *exmdbc_client_create()
{
	fprintf(stdout, "!!! exmdbc_client_create called\n");
	struct exmdb_client *client = NULL;
	if (exmdb_client_create(&client) != 0) {
		return NULL;
	}
	fprintf(stdout, "!!! exmdbc_client_create finished\n");
	return client;
}

static void exmdbc_client_free(struct exmdb_client * client)
{
	fprintf(stdout, "!!! exmdbc_client_free called\n");
	exmdb_client_free(&client);
}

static int exmdbc_storage_create(struct mail_storage *_storage,
                                 const struct mail_namespace *ns,
                                 const char **error_r)
{
	fprintf(stdout, "!!! exmdbc_storage_create called\n");
	if (strcmp(ns->list->name, EXMDBC_STORAGE_NAME) != 0) {
		i_warning("exmdbc: unexpected namespace name: %s", ns->list->name);
	}
	i_warning("exmdbc: prefix: %s", ns->prefix);
	i_warning("exmdbc: list->mail_set->mail_path: %s", ns->list->mail_set->mail_path);
	i_warning("exmdbc: list->mail_set->mail_inbox_path: %s", ns->list->mail_set->mail_inbox_path);

	struct exmdbc_storage *storage = EXMDBC_STORAGE(_storage);

	const char *mail_path = ns->list->mail_set->mail_path;
	if (!mail_path) {
		fprintf(stdout, "!!! exmdbc: no mail_path provided in config\n");
		*error_r = "exmdbc: no mail_path provided in config";
		return -1;
	}


	struct exmdbc_mailbox_list *exmdbc_list = NULL;
	exmdbc_list = (struct exmdbc_mailbox_list *)ns->list;
	storage->client = exmdbc_list->client;
	storage->client->refcount++;


	exmdb_client_set_dir(storage->client->client, mail_path);
	storage->mailbox_dir = p_strdup(_storage->pool, mail_path);

	storage->client->_storage = storage;


	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		fprintf(stdout, "!!! exmdbc: ns->flags & NAMESPACE_FLAG_INBOX_USER != 0\n");
	}
	if (storage->client == NULL) {
		*error_r = "exmdbc_client_create() failed";
		return -1;
	}
	p_array_init(&storage->remote_namespaces, _storage->pool, 4);

	const char *username = _storage->user->username;

	_storage->unique_root_dir = p_strdup_printf(_storage->pool,
		"exmdbc://%s", username);
	i_warning("exmdbc_storage_create: unique_root_dir: %s", _storage->unique_root_dir);

	i_info("exmdbc_storage_create(): connected as user=%s", username);

	return 0;
}


static void exmdbc_storage_destroy(struct mail_storage *_storage)
{
	fprintf(stdout, "!!! exmdbc_storage_destroy called\n");
	struct exmdbc_storage *storage = (struct exmdbc_storage *)_storage;

	if (storage->client != NULL) {
		i_info("exmdbc_storage_destroy(): disconnecting client");
		exmdbc_client_free(storage->client->client);
	}

	i_info("exmdbc_storage_destroy(): storage for user %s cleaned up",
	       _storage->user ? _storage->user->username : "(unknown)");
}
static int exmdbc_storage_add_list(struct mail_storage *_storage,
								   struct mailbox_list *list)
{
	fprintf(stdout, "!!! exmdbc_storage_destroy called\n");
	struct exmdbc_storage *_s = (struct exmdbc_storage *)_storage;
	_s->client->_list = (struct exmdbc_mailbox_list *)list;
	return 0;
}


struct mail_storage exmdbc_storage = {
	.name = EXMDBC_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_NO_LIST_DELETES |
				   MAIL_STORAGE_CLASS_FLAG_BINARY_DATA |
				   MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT |
				   MAIL_STORAGE_CLASS_FLAG_NOQUOTA,
	
	.v = {
		exmdbc_storage_alloc,
		exmdbc_storage_create,
		exmdbc_storage_destroy,
		exmdbc_storage_add_list,
		NULL,
		exmdbc_mailbox_alloc,
		NULL,
		NULL,
	}
};

struct mailbox *
exmdbc_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
					 const char *vname, enum mailbox_flags flags)
{
	fprintf(stdout, "!!! exmdbc_mailbox_alloc called\n");
	pool_t pool = pool_alloconly_create("exmdbc mailbox", 4096);
	struct exmdbc_mailbox *mbox = p_new(pool, struct exmdbc_mailbox, 1);

	struct exmdbc_mailbox_list *_list = (struct exmdbc_mailbox_list *)list;

	mbox->box = exmdbc_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.flags = flags;
	mbox->box.mail_vfuncs = &exmdbc_mail_vfuncs;

	if (_list->folder_map_initialized != TRUE)
	{
		pool_t pool1 = pool_alloconly_create("mailbox list exmdbc iter", 2048);

		struct exmdbc_mailbox_list_iterate_context *ctx =
			p_new(pool1, struct exmdbc_mailbox_list_iterate_context, 1);

		ctx->ctx.pool = pool1;
		ctx->ctx.list = mbox->box.list;
		ctx->ctx.flags = 0;
		ctx->next_index = 0;

		array_create(&ctx->ctx.module_contexts, pool1, sizeof(void *), 5);

		int ret = exmdbc_list_refresh(_list, ctx);
		if (ret < 0) {
			mail_storage_set_internal_error(mbox->box.storage);
			pool_unref(&pool1);
			return NULL;
		}
		pool_unref(&pool1);
	}
	const char *lower_name = t_str_lcase(vname);
	void *val = hash_table_lookup(_list->folder_id_map, lower_name);
	if (val == NULL) {
		return NULL;
	}
	mbox->folder_id = (uint64_t)(uintptr_t)val;

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	mbox->storage = (struct exmdbc_storage *)storage;

	const int ret = exmdbc_client_ping_store(mbox->storage->mailbox_dir);
	if (ret == FALSE) {
		mail_storage_set_error(storage, MAIL_ERROR_NOTFOUND,
					   "ping_store failed");
		return NULL;
	}
	i_info("exmdbc_mailbox_alloc ping_store complete\n");
	mbox->prev_mail_cache.fd = -1;

	i_info("exmdbc_mailbox_alloc(): mailbox '%s' allocated", vname);
	return &mbox->box;
}

const char *exmdbc_mailbox_get_remote_name(const struct exmdbc_mailbox *mbox) {
	fprintf(stdout, "!!! exmdbc_mailbox_get_remote_name called\n");
	return mbox->box.name;
}

static int exmdbc_mailbox_exists(struct mailbox *box, bool auto_boxes, enum mailbox_existence *existence_r) {
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)box->list;
	const char *name = box->name;

	fprintf(stderr, "!!! exmdbc_mailbox_exists: checking mailbox '%s'\n", name);

	if (auto_boxes && mailbox_is_autocreated(box)) {
		*existence_r = MAILBOX_EXISTENCE_SELECT;
		return 0;
	}

	if (!list->refreshed_mailboxes) {

		struct exmdbc_mailbox_list_iterate_context *ctx =
			p_new(list->list.pool, struct exmdbc_mailbox_list_iterate_context, 1);

		ctx->ctx.pool = list->list.pool;
		ctx->ctx.list = box->list;
		ctx->ctx.flags = 0;
		ctx->next_index = 0;

		array_create(&ctx->ctx.module_contexts, list->list.pool, sizeof(void *), 5);
		if (exmdbc_list_refresh(list, ctx) < 0) {
			pool_unref(&list->list.pool);
			mail_storage_set_internal_error(box->storage);
			return -1;
		}
	}

	const char *lower_name = t_str_lcase(name);
	void *folder_id_ptr = hash_table_lookup(list->folder_id_map, lower_name);
	if (folder_id_ptr != NULL) {
		*existence_r = MAILBOX_EXISTENCE_SELECT;
		return 0;
	}

	*existence_r = MAILBOX_EXISTENCE_NONE;
	return 0;
}

int exmdbc_mailbox_select(struct exmdbc_mailbox *mbox) {
	fprintf(stdout, "!!! exmdbc_mailbox_select called\n");


	i_assert(mbox->client_box == NULL);

	if (exmdbc_mailbox_has_modseqs(mbox)) {
		if (!array_is_created(&mbox->rseq_modseqs))
			i_array_init(&mbox->rseq_modseqs, 32);
		else
			array_clear(&mbox->rseq_modseqs);
	}

	struct exmdbc_folder_dto;

	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)mbox->box.list;
	const char *username = list->list.ns->user->username;
	struct exmdb_folder_metadata folder_meta;
	if (exmdbc_client_get_folder_dtos(list->client->client, mbox->folder_id, &folder_meta, username) < 0)
		return -1;

	mbox->exists_count = folder_meta.num_messages;

	mbox->selecting = FALSE;
	if (mbox->exists_count == 0) {
		mbox->sync_next_lseq = 1;
	} else {
		(void)exmdbc_mailbox_fetch_state(mbox, 1);
	}
	mbox->selecting = FALSE;
	mbox->exists_received = TRUE;
	// Replacing exmdbc_mailbox_open_callback() by manual calling fetch_state

	exmdbc_mailbox_select_finish(mbox);
	return 0;
}

static int exmdbc_mailbox_open(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_mailbox_open called\n");
	struct exmdbc_storage *storage = EXMDBC_STORAGE(box->storage);
	struct exmdbc_mailbox *mbox   = EXMDBC_MAILBOX(box);
	i_info("exmdbc_mailbox_open(): called");

	if (index_storage_mailbox_open(box, FALSE) < 0)
		return -1;

	if (box->deleting || (box->flags & MAILBOX_FLAG_SAVEONLY) != 0) {
		/* We don't actually want to SELECT the mailbox. */
		return 0;
	}

	i_warning("exmdbc_mailbox_open: mail dir: %s", storage->mailbox_dir);
	const int ret = exmdbc_client_ping_store(storage->mailbox_dir);
	if (ret == FALSE) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
					   "Cannot ping store");
		return -1;
	}
	fprintf(stdout, "!!! exmdbc_mailbox_alloc ping_store complete\n");

	if (exmdbc_mailbox_select(mbox) < 0) {
		mailbox_close(box);
		return -1;
	}

	return 0;
}

void exmdbc_mail_cache_free(struct exmdbc_mail_cache *cache) {
	fprintf(stdout, "!!! exmdbc_mail_cache_free called\n");
	// i_close_fd(&cache->fd);
	buffer_free(&cache->buf);
	cache->uid = 0;
}

static void exmdbc_mailbox_close(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_mailbox_close called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(box);
	exmdbc_mail_fetch_flush(mbox);

	if (array_is_created(&mbox->rseq_modseqs))
		array_free(&mbox->rseq_modseqs);
	if (mbox->sync_view != NULL)
		mail_index_view_close(&mbox->sync_view);
	exmdbc_mail_cache_free(&mbox->prev_mail_cache);
	index_storage_mailbox_close(box);
}

static int
exmdbc_mailbox_create(struct mailbox *box, const struct mailbox_update *update ATTR_UNUSED, bool directory) {
	fprintf(stdout, "!!! exmdbc_mailbox_create called\n");

	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(box);
	struct exmdbc_storage *storage = mbox->storage;
	unsigned long folderId;

	if (!directory) {

		fprintf(stdout, "!!! exmdbc_mailbox_create directory not exist\n");
		return -1;
	}
	char *fullpath = p_strdup_printf(box->pool,
	                                 "%s/%hhd",
	                                 storage->storage.unique_root_dir,
	                                 directory);

	const int ret = exmdbc_client_ping_store(storage->mailbox_dir);
	if (ret == FALSE) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
					   "ping_store failed");
		return -1;
	}
	fprintf(stdout, "!!! exmdbc_mailbox_alloc ping_store complete\n");


	if (!exmdbc_client_create_folder_v1(storage->client->client,
								  fullpath,
								  /* cpid */ 0,
								  /* no props */ 0,
								  &folderId))
	{
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
					   "Failed to create folder");
		return -1;
	}
	return 0;
}

static int exmdbc_mailbox_update(struct mailbox *box, const struct mailbox_update *update) {
	fprintf(stdout, "!!! exmdbc_mailbox_update called\n");
	if (!guid_128_is_empty(update->mailbox_guid) ||
		update->uid_validity != 0 || update->min_next_uid != 0 ||
		update->min_first_recent_uid != 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
					   "Not supported");
		}
	return index_storage_mailbox_update(box, update);
}

static int exmdbc_mailbox_delete(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_mailbox_delete called\n");
	box->delete_skip_empty_check = TRUE;
	return index_storage_mailbox_delete(box);
}

static int exmdbc_mailbox_get_metadata(struct mailbox *box, enum mailbox_metadata_items items, struct mailbox_metadata *metadata_r) {
	fprintf(stdout, "!!! exmdbc_mailbox_get_metadata called\n");
	return -1;
}

static void exmdbc_notify_changes(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_notify_changes called\n");

}

static bool exmdbc_is_inconsistent(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_is_inconsistent called\n");
	return FALSE;
}

void exmdbc_mailbox_run(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_run called\n");
	exmdbc_mail_fetch_flush(mbox);
}

struct mailbox exmdbc_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_mailbox_enable,
		exmdbc_mailbox_exists,
		exmdbc_mailbox_open,
		exmdbc_mailbox_close,
		index_storage_mailbox_free,
		exmdbc_mailbox_create,
		exmdbc_mailbox_update,
		exmdbc_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		exmdbc_mailbox_get_metadata,
		index_storage_set_subscribed,
		exmdbc_storage_attribute_set,
		exmdbc_storage_attribute_get,
		exmdbc_storage_attribute_iter_init,
		exmdbc_storage_attribute_iter_next,
		exmdbc_storage_attribute_iter_deinit,
		NULL,
		NULL,
		exmdbc_mailbox_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		exmdbc_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		NULL,
		exmdbc_mail_alloc,
		exmdbc_search_init,
		exmdbc_search_deinit,
		index_storage_search_next_nonblock,
		exmdbc_search_next_update_seq,
		index_storage_search_next_match_mail,
		exmdbc_save_alloc,
		exmdbc_save_begin,
		exmdbc_save_continue,
		exmdbc_save_finish,
		exmdbc_save_cancel,
		exmdbc_copy,
		exmdbc_transaction_save_commit_pre,
		exmdbc_transaction_save_commit_post,
		exmdbc_transaction_save_rollback,
		exmdbc_is_inconsistent
	}
};

