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

static bool exmdbc_client_connect(struct exmdb_client * client)
{
	fprintf(stdout, "!!! exmdbc_client_connect called\n");
	//USE GROMOX SDK
	return FALSE;
}

static bool exmdbc_client_login(struct exmdb_client * client, const char *username)
{
	fprintf(stdout, "!!! exmdbc_client_login called\n");

	//For exmdb we don't need special login. Instead we can do ping storage by mail_sir but im already doing this in another place
	return TRUE;
}

static void exmdbc_client_free(struct exmdb_client * client)
{
	fprintf(stdout, "!!! exmdbc_client_free called\n");
	exmdb_client_free(&client);
}

static int exmdbc_storage_create(struct mail_storage *_storage,
                                 struct mail_namespace *ns,
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
	if (exmdbc_client_login(storage->client->client, username) < 0) {
		*error_r = t_strdup_printf("exmdb_client_login() failed for user %s", username);
		return -1;
	}

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
		pool_t pool = pool_alloconly_create("mailbox list exmdbc iter", 2048);

		struct exmdbc_mailbox_list_iterate_context *ctx =
			p_new(pool, struct exmdbc_mailbox_list_iterate_context, 1);

		ctx->ctx.pool = pool;
		ctx->ctx.list = mbox->box.list; // вже містить exmdbc_mailbox_list
		ctx->ctx.flags = 0;
		ctx->list_ctx.next_index = 0;

		array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);

		int ret = exmdbc_list_refresh(_list, ctx);
		if (ret < 0) {
			mail_storage_set_internal_error(mbox->box.storage);
			pool_unref(&pool);
			return NULL;
		}
		pool_unref(&pool);
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

	p_array_init(&mbox->untagged_callbacks, pool, 16);
	p_array_init(&mbox->resp_text_callbacks, pool, 16);
	p_array_init(&mbox->fetch_requests, pool, 16);
	p_array_init(&mbox->untagged_fetch_contexts, pool, 16);
	p_array_init(&mbox->delayed_expunged_uids, pool, 16);
	p_array_init(&mbox->copy_rollback_expunge_uids, pool, 16);
	mbox->pending_fetch_cmd = str_new(pool, 128);
	mbox->pending_copy_cmd = str_new(pool, 128);
	mbox->prev_mail_cache.fd = -1;
	exmdbc_mailbox_register_callbacks(mbox);

	i_info("exmdbc_mailbox_alloc(): mailbox '%s' allocated", vname);
	return &mbox->box;
}

const char *exmdbc_mailbox_get_remote_name(struct exmdbc_mailbox *mbox) {
	fprintf(stdout, "!!! exmdbc_mailbox_get_remote_name called\n");
	return mbox->box.name;
}

static int
exmdbc_mailbox_exists(struct mailbox *box, bool auto_boxes, enum mailbox_existence *existence_r) {
	fprintf(stdout, "!!! exmdbc_mailbox_exists called\n");

	struct exmdbc_storage *storage = EXMDBC_STORAGE(box->storage);
	const int ret = exmdbc_client_ping_store(storage->mailbox_dir);

	if (ret == FALSE) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
					   "Cannot ping store");
		return -1;
	}
	return 0;
}

static bool exmdbc_mailbox_want_examine(struct exmdbc_mailbox *mbox) {
	fprintf(stdout, "!!! exmdbc_mailbox_want_examine called\n");
	return FALSE;
}

static bool
exmdbc_mailbox_verify_select(struct exmdbc_mailbox *mbox, const char **error_r) {
	fprintf(stdout, "!!! exmdbc_mailbox_verify_select called\n");
	return FALSE;
}

static void
exmdbc_mailbox_reopen_callback(const struct exmdbc_command_reply *reply, void *context) {
	fprintf(stdout, "!!! exmdbc_mailbox_reopen_callback called\n");

}

static void exmdbc_mailbox_reopen(void *context) {
	fprintf(stdout, "!!! exmdbc_mailbox_reopen called\n");

}

static void
exmdbc_mailbox_open_callback(const struct exmdbc_command_reply *reply, void *context) {
	fprintf(stdout, "!!! exmdbc_mailbox_open_callback called\n");

}

static int exmdbc_mailbox_get_capabilities(struct exmdbc_mailbox *mbox) {
	fprintf(stdout, "!!! exmdbc_mailbox_get_capabilities called\n");
	/* If authentication failed, don't check again. */
		return -1;
}

static void exmdbc_mailbox_get_extensions(struct exmdbc_mailbox *mbox) {
	fprintf(stdout, "!!! exmdbc_mailbox_get_extensions called\n");
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

	struct exmdbc_folder_dto tmp_array[128];
	unsigned int tmp_count = 0;


	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)mbox->box.list;
	const char *username = list->list.ns->user->username;
	struct exmdb_folder_metadata folder_meta;
	if (exmdbc_client_get_folder_dtos(list->client->client, mbox->folder_id, &folder_meta, username) < 0)
		return -1;

	mbox->exists_count = folder_meta.num_messages;
	// exmdbc_mailbox_set_highest_modseq(mbox, modseq);
	// exmdbc_mailbox_set_uidvalidity(mbox, uidvalidity);
	// exmdbc_mailbox_set_uidnext(mbox, next_uid);

	mbox->selecting = FALSE;
	if (mbox->exists_count == 0) {
		/* no mails. expunge everything. */
		mbox->sync_next_lseq = 1;
		// exmdbc_mailbox_init_delayed_trans(mbox);
		// exmdbc_mailbox_fetch_state_finish(mbox);
	} else {
		/* We don't know the latest flags, refresh them. */
		(void)exmdbc_mailbox_fetch_state(mbox, 1);
	}
	mbox->selected = TRUE;
	mbox->exists_received = TRUE;
	mbox->selected = TRUE;

	return 0;
}

static int exmdbc_mailbox_open(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_mailbox_open called\n");
	struct exmdbc_storage *storage = EXMDBC_STORAGE(box->storage);
	struct exmdbc_mailbox *mbox   = EXMDBC_MAILBOX(box);

	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)box->list;
	i_info("exmdbc_mailbox_open(): called");

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
	i_close_fd(&cache->fd);
	buffer_free(&cache->buf);
	cache->uid = 0;
}

static void exmdbc_mailbox_close(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_mailbox_close called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(box);
	bool changes;

	(void)exmdbc_mailbox_commit_delayed_trans(mbox, FALSE, &changes);
	exmdbc_mail_fetch_flush(mbox);

	/* Arriving here we may have fetch contexts still unprocessed,
	   if there have been no mailbox_sync() after receiving the untagged replies.
	   Losing these changes isn't a problem, since the same changes will be found
	   out after connecting to the server the next time. */
	struct exmdbc_untagged_fetch_ctx *untagged_fetch_context;
	array_foreach_elem(&mbox->untagged_fetch_contexts, untagged_fetch_context)
		exmdbc_untagged_fetch_ctx_free(&untagged_fetch_context);
	array_clear(&mbox->untagged_fetch_contexts);

//TODO:EXMDC:
//	if (mbox->client_box != NULL)
//		exmdbc_client_mailbox_close(&mbox->client_box);
	if (array_is_created(&mbox->rseq_modseqs))
		array_free(&mbox->rseq_modseqs);
	if (mbox->sync_view != NULL)
		mail_index_view_close(&mbox->sync_view);
	timeout_remove(&mbox->to_idle_delay);
	timeout_remove(&mbox->to_idle_check);
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
	                                 "%s/%s",
	                                 storage->storage.unique_root_dir,
	                                 directory);

	const int ret = exmdbc_client_ping_store(storage->mailbox_dir);
	if (ret == FALSE) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
					   "ping_store failed");
		return -1;
	}
	fprintf(stdout, "!!! exmdbc_mailbox_alloc ping_store complete\n");


	if (!exmdbc_client_create_folder_v1(storage->client,
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

static void exmdbc_untagged_namespace(const struct exmdbc_untagged_reply *reply, struct exmdbc_storage_client *client) {
	fprintf(stdout, "!!! exmdbc_untagged_namespace called\n");

}

static void
exmdbc_parse_inprogress_start_time(struct exmdbc_storage_client *client, const char *tag, struct mail_storage_progress_details *detail_r) {
	fprintf(stdout, "!!! exmdbc_parse_inprogress_start_time called\n");

}

static void exmdbc_parse_inprogress(const struct exmdbc_untagged_reply *reply, struct exmdbc_storage_client *client, struct mail_storage_progress_details *detail_r) {
	fprintf(stdout, "!!! exmdbc_parse_inprogress called\n");

}

static void exmdbc_untagged_inprogress(const struct exmdbc_untagged_reply *reply, struct exmdbc_storage_client *client) {
	fprintf(stdout, "!!! exmdbc_untagged_inprogress called\n");

}

static void exmdbc_mailbox_get_selected_status(struct exmdbc_mailbox *mbox, enum mailbox_status_items items, struct mailbox_status *status_r) {
	fprintf(stdout, "!!! exmdbc_mailbox_get_selected_status called\n");

}

static int exmdbc_mailbox_delete(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_mailbox_delete called\n");
	box->delete_skip_empty_check = TRUE;
	return index_storage_mailbox_delete(box);
}

static int exmdbc_mailbox_run_status(struct mailbox *box, enum mailbox_status_items items, struct mailbox_status *status_r) {
	fprintf(stdout, "!!! exmdbc_mailbox_run_status called\n");

}

static int exmdbc_mailbox_get_status(struct mailbox *box, enum mailbox_status_items items, struct mailbox_status *status_r) {
	fprintf(stdout, "!!! exmdbc_mailbox_get_status called\n");

}

static int exmdbc_mailbox_get_namespaces(struct exmdbc_mailbox *mbox) {
	fprintf(stdout, "!!! exmdbc_mailbox_get_namespaces called\n");

}

static const struct exmdbc_namespace * exmdbc_namespace_find_mailbox(struct exmdbc_storage *storage, const char *remote_name) {
	fprintf(stdout, "!!! exmdbc_namespace_find_mailbox called\n");
	const struct exmdbc_namespace *ns, *best_ns = NULL;
	size_t best_len = UINT_MAX, len;

	array_foreach(&storage->remote_namespaces, ns) {
		len = strlen(ns->prefix);
		if (str_begins_with(remote_name, ns->prefix)) {
			if (best_len > len) {
				best_ns = ns;
				best_len = len;
			}
		}
	}
	return best_ns;
}

static int exmdbc_mailbox_get_metadata(struct mailbox *box, enum mailbox_metadata_items items, struct mailbox_metadata *metadata_r) {
	fprintf(stdout, "!!! exmdbc_mailbox_get_metadata called\n");

}

static void exmdbc_noop_callback(const struct exmdbc_command_reply *reply, void *context) {
	fprintf(stdout, "!!! exmdbc_noop_callback called\n");

}

static void exmdbc_idle_timeout(struct exmdbc_mailbox *mbox) {
	fprintf(stdout, "!!! exmdbc_idle_timeout called\n");

}

static void exmdbc_idle_noop_callback(const struct exmdbc_command_reply *reply, void *context) {
	fprintf(stdout, "!!! exmdbc_idle_noop_callback called\n");
	struct exmdbc_mailbox *mbox = context;
}

static void exmdbc_notify_changes(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_notify_changes called\n");

}

static bool exmdbc_is_inconsistent(struct mailbox *box) {
	fprintf(stdout, "!!! exmdbc_is_inconsistent called\n");
	return FALSE;
}

static int
exmdbc_mailbox_transaction_commit(struct mailbox_transaction_context *t, struct mail_transaction_commit_changes *changes_r)
{
	fprintf(stdout, "!!! exmdbc_mailbox_transaction_commit called\n");
	int ret = exmdbc_transaction_save_commit(t);
	int ret2 = index_transaction_commit(t, changes_r);
	return ret >= 0 && ret2 >= 0 ? 0 : -1;
}

void exmdbc_simple_context_init(struct exmdbc_simple_context *sctx,
				   struct exmdbc_storage_client *client)
{
	fprintf(stdout, "!!! exmdbc_simple_context_init called\n");
	i_zero(sctx);
	sctx->client = client;
	sctx->ret = -2;
}

void exmdbc_mailbox_run(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_run called\n");
	exmdbc_mail_fetch_flush(mbox);
	exmdbc_mailbox_run_nofetch(mbox);
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
		exmdbc_mailbox_get_status,
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
		exmdbc_mailbox_sync_deinit,
		NULL,
		exmdbc_notify_changes,
		index_transaction_begin,
		exmdbc_mailbox_transaction_commit,
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

