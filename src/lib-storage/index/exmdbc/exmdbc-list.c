#include "lib.h"
#include "mailbox-list-private.h"
#include "exmdbc-list.h"

#include <dsasl-client.h>
#include <exmdbc-storage.h>
#include <exmdbc-settings.h>
#include <settings.h>
#include <stdio.h>
#include <str.h>
#include <src/lib-imap-client/imapc-client.h>
#include <src/lib-imap-client/imapc-settings.h>

#include "mail-storage-service.h"
#include "mailbox-tree.h"
#include "mailbox-list-subscriptions.h"
#include "exmdb_client_c.h"

#define MAX_MAILBOXES 128
#define DNS_CLIENT_SOCKET_NAME "dns-client"

struct exmdbc_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_info mailboxes[MAX_MAILBOXES];
	unsigned int mailbox_count;
	unsigned int next_index;
};

static void exmdbc_list_send_hierarchy_sep_lookup(struct exmdbc_mailbox_list *list);

int exmdbc_list_fill_mailbox_info(pool_t pool, struct exmdb_client *client,
								   const char *username,
								   struct mailbox_info *out_array,
								   unsigned int max_count,
								   unsigned int *out_count)
{
	struct exmdbc_folder_dto tmp_array[128];
	unsigned int tmp_count = 0;

	if (exmdbc_client_get_folder_dtos(client, tmp_array, username, 128, &tmp_count) < 0)
		return -1;

	*out_count = 0;

	for (unsigned int i = 0; i < tmp_count && *out_count < max_count; ++i) {
		struct mailbox_info *info = &out_array[(*out_count)++];
		memset(info, 0, sizeof(*info));

		info->vname = p_strdup(pool, tmp_array[i].name);
		info->flags = MAILBOX_NOSELECT;
	}

	return 0;
}

static int exmdbc_list_refresh(struct exmdbc_mailbox_list *list, struct exmdbc_list_iterate_context *ctx) {
	fprintf(stdout, "!!! exmdbc_list_refresh called\n");

	unsigned int count = 0;

	const char *user = list->list.ns->user->username;
	if (exmdbc_list_fill_mailbox_info(ctx->ctx.pool, list->client->client, user, ctx->mailboxes, MAX_MAILBOXES, &count) < 0)
		return -1;
	ctx->mailbox_count = count;
}

struct mailbox_list_iterate_context *
exmdbc_list_iter_init(struct mailbox_list *_list, const char *const *patterns,
                      enum mailbox_list_iter_flags flags)
{
	fprintf(stdout, "!!! exmdbc_list_iter_init called\n");
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)_list;

	pool_t pool = pool_alloconly_create("exmdbc iter", 2048);
	struct exmdbc_list_iterate_context *ctx = p_new(pool, struct exmdbc_list_iterate_context, 1);
	ctx->ctx.pool = pool;
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->next_index = 0;
	array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);

	if (exmdbc_list_refresh(list, ctx) < 0) {
		ctx->ctx.failed = TRUE;
	}

	return &ctx->ctx;
}

const struct mailbox_info *
exmdbc_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_list_iter_next called\n");
	struct exmdbc_list_iterate_context *ctx = (struct exmdbc_list_iterate_context *)_ctx;

	if (ctx->next_index >= ctx->mailbox_count)
		return NULL;

	return &ctx->mailboxes[ctx->next_index++];
}

int exmdbc_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_list_iter_deinit called\n");
	struct exmdbc_list_iterate_context *ctx = (struct exmdbc_list_iterate_context *)_ctx;
	pool_unref(&ctx->ctx.pool);
	return 0;
}


static struct mailbox_list *exmdbc_list_alloc(void)
{
	fprintf(stdout, "!!! exmdbc_list_alloc called\n");
	struct exmdbc_mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("exmdbc mailbox list", 1024);
	list = p_new(pool, struct exmdbc_mailbox_list, 1);
	list->list = exmdbc_mailbox_list;
	list->list.pool = pool;
	/* separator is set lazily */
	list->mailboxes = mailbox_tree_init('\0');
	mailbox_tree_set_parents_nonexistent(list->mailboxes);
	return &list->list;
}

static int exmdbc_list_init(struct mailbox_list *_list, const char **error_r)
{
	fprintf(stdout, "!!! exmdbc_list_init called\n");
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)_list;

	exmdbc_storage_client_create(_list, &list->client, error_r);
	list->client->_list = list;

	if ((_list->ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		/* Avoid connecting to exmdbc just to access mailbox names.
		   There are no mailboxes, so the separator doesn't matter. */
		list->root_sep = '/';
	}
	return 0;
}

void exmdbc_storage_client_create(struct mailbox_list *list,
                                  struct exmdbc_storage_client **client_r,
                                  const char **error_r)
{
	fprintf(stdout, "!!! exmdbc_storage_client_create called\n");

	struct exmdbc_storage_client *client = i_new(struct exmdbc_storage_client, 1);
	client->client = exmdbc_client_create();

	*client_r = client;
}

void exmdbc_storage_client_unref(struct exmdbc_storage_client **_client)
{
	fprintf(stdout, "exmdbc_storage_client_unref called\n");
	struct exmdbc_storage_client *client = *_client;

	*_client = NULL;

	i_free(client->auth_failed_reason);
	i_free(client);
}

void exmdbc_list_deinit(struct mailbox_list * _list)
{
	fprintf(stdout, "!!! exmdbc_list_deinit called\n");
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)_list;

	/* make sure all pending commands are aborted before anything is
	   deinitialized */
	if (list->client != NULL) {
		list->client->destroying = TRUE;
		//TODO:EXMDBC:
		// imapc_client_logout(list->client->imapc_client);
		exmdbc_storage_client_unref(&list->client);
	}
	if (list->index_list != NULL)
		mailbox_list_destroy(&list->index_list);
	mailbox_tree_deinit(&list->mailboxes);
	if (list->tmp_subscriptions != NULL)
		mailbox_tree_deinit(&list->tmp_subscriptions);
	pool_unref(&list->list.pool);
}

void exmdbc_untagged_lsub(const struct exmdbc_untagged_reply *reply, struct exmdbc_storage_client *client) {
	fprintf(stdout, "!!! exmdbc_untagged_lsub called\n");
}

int exmdbc_list_try_get_root_sep(struct exmdbc_mailbox_list *list, char *sep_r)
{
	fprintf(stdout, "!!! exmdbc_list_try_get_root_sep called\n");
	if (list->root_sep == '\0') {
		if (exmdbc_storage_client_handle_auth_failure(list->client))
			return -1;

		//TODO:EXMDBC:
		// while (list->root_sep_pending)
		// 	exmdbc_client_run(list->client->client);
		if (list->root_sep == '\0')
			return -1;
	}
	*sep_r = list->root_sep;
	return 0;
}

char exmdbc_list_get_hierarchy_sep(struct mailbox_list * _list)
{
	fprintf(stdout, "!!! exmdbc_list_get_hierarchy_sep called\n");
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)_list;
	char sep;

	if (exmdbc_list_try_get_root_sep(list, &sep) < 0) {
		/* we can't really return a failure here. just return a common
		   separator and fail all the future list operations. */
		return '/';
	}
	return sep;
}

static const char *
exmdbc_list_get_vname(struct mailbox_list *list, const char *name)
{
	fprintf(stdout, "!!! exmdbc_list_get_vname called\n");
	return list->v.get_vname(list, name);
}

static const char *
exmdbc_list_get_storage_name(struct mailbox_list *list, const char *vname)
{
	fprintf(stdout, "!!! exmdbc_list_get_storage_name called\n");
	i_debug("exmdbc: get_storage_name: name=%s", vname);
	return p_strdup(list->pool, vname);
}
static int
exmdbc_list_get_path(struct mailbox_list *_list, const char *name,
					 enum mailbox_list_path_type type, const char **path_r)
{
	fprintf(stdout, "!!! exmdbc_list_get_path called\n");
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)_list;
	const char *base_dir = list->list.mail_set->mail_path;

	if (base_dir == NULL || *base_dir == '\0') {
		i_warning("exmdbc_list_get_path: mail_path is empty!");
		*path_r = NULL;
		return -1;
	}

	if (name == NULL || *name == '\0') {
		i_warning("exmdbc_list_get_path: name is empty!");
		name = ".INBOX";
	}
	switch (type) {
		case MAILBOX_LIST_PATH_TYPE_DIR:
		case MAILBOX_LIST_PATH_TYPE_ALT_DIR:
			*path_r = t_strdup_printf("%s/%s", base_dir, name);
		break;
		case MAILBOX_LIST_PATH_TYPE_MAILBOX:
		case MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX:
			*path_r = t_strdup_printf("%s/%s/messages", base_dir, name);
		break;
		case MAILBOX_LIST_PATH_TYPE_CONTROL:
			*path_r = t_strdup_printf("%s/.control", base_dir);
		break;
		case MAILBOX_LIST_PATH_TYPE_INDEX:
		case MAILBOX_LIST_PATH_TYPE_INDEX_CACHE:
		case MAILBOX_LIST_PATH_TYPE_LIST_INDEX:
			*path_r = t_strdup_printf("%s/.index", base_dir);
		break;
		case MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE:
			*path_r = NULL;
		break;
		default:
			*path_r = NULL;
		break;
	}

	i_debug("exmdbc: get_path: name=%s type=%d -> %s",
			name, type, *path_r ? *path_r : "(null)");
	return 0;
}

static const char *
exmdbc_list_get_temp_prefix(struct mailbox_list *list)
{
	fprintf(stdout, "!!! exmdbc_list_get_temp_prefix called\n");
	return list->v.get_temp_prefix(list, FALSE);
}

static const char *
exmdbc_list_join_refpattern(struct mailbox_list *list ATTR_UNUSED,
			   const char *ref, const char *pattern)
{
	fprintf(stdout, "!!! exmdbc_list_join_refpattern called\n");
	if (list->v.join_refpattern != NULL)
		return list->v.join_refpattern(list, ref, pattern);

	/* the default implementation: */
	if (*ref != '\0') {
		/* merge reference and pattern */
		pattern = t_strconcat(ref, pattern, NULL);
	}
	return pattern;
}

static int
exmdbc_list_subscriptions_refresh(struct mailbox_list *_src_list,
				 struct mailbox_list *dest_list)
{
	fprintf(stdout, "!!! exmdbc_list_subscriptions_refresh called\n");
	struct exmdbc_mailbox_list *src_list =
		(struct exmdbc_mailbox_list *)_src_list;
	struct exmdbc_simple_context ctx;
	struct exmdbc_command *cmd;
	const char *pattern;
	char list_sep, dest_sep = mail_namespace_get_sep(dest_list->ns);

	i_assert(src_list->tmp_subscriptions == NULL);

	if (exmdbc_list_try_get_root_sep(src_list, &list_sep) < 0)
		return -1;

	if (src_list->refreshed_subscriptions ||
		(src_list->list.ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		if (dest_list->subscriptions == NULL)
			dest_list->subscriptions = mailbox_tree_init(dest_sep);
		return 0;
		}

	src_list->tmp_subscriptions =
		mailbox_tree_init(mail_namespace_get_sep(_src_list->ns));

	//TODO:EXMDBC:
	// cmd = exmdbc_list_simple_context_init(&ctx, src_list);
	// if (*src_list->set->exmdbc_list_prefix == '\0')
	// 	pattern = "*";
	// else
	// 	pattern = t_strdup_printf("%s*", src_list->set->exmdbc_list_prefix);
	// exmdbc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	// exmdbc_command_sendf(cmd, "LSUB \"\" %s", pattern);
	// exmdbc_simple_run(&ctx, &cmd);

	if (ctx.ret < 0)
		return -1;

	/* replace subscriptions tree in destination */
	if (dest_list->subscriptions != NULL)
		mailbox_tree_deinit(&dest_list->subscriptions);
	dest_list->subscriptions = src_list->tmp_subscriptions;
	src_list->tmp_subscriptions = NULL;
	mailbox_tree_set_separator(dest_list->subscriptions, dest_sep);

	src_list->refreshed_subscriptions = TRUE;
	return 0;
}

static int exmdbc_list_set_subscribed(struct mailbox_list *_list,
					 const char *name, bool set)
{
	fprintf(stdout, "!!! exmdbc_list_set_subscribed called\n");
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)_list;
	struct exmdbc_command *cmd;
	struct exmdbc_simple_context ctx;

	//TODO:EXMDBC:
	// cmd = exmdbc_list_simple_context_init(&ctx, list);
	// exmdbc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	// exmdbc_command_sendf(cmd, set ? "SUBSCRIBE %s" : "UNSUBSCRIBE %s",
	// 			exmdbc_list_storage_to_remote_name(list, name));
	// exmdbc_simple_run(&ctx, &cmd);
	return ctx.ret;
}

static int
exmdbc_list_delete_mailbox(struct mailbox_list *_list, const char *name)
{
	fprintf(stdout, "!!! exmdbc_list_delete_mailbox called\n");
	//TODO:EXMDBC:
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)_list;
	//struct mailbox_list *fs_list = exmdbc_list_get_fs(list);
	// enum exmdbc_capability capa;
	struct exmdbc_command *cmd;
	struct exmdbc_simple_context ctx;

	// if (exmdbc_storage_client_handle_auth_failure(list->client))
	// 	return -1;
	// if (exmdbc_client_get_capabilities(list->client->client, &capa) < 0)
	// 	return -1;
	//
	// cmd = exmdbc_list_simple_context_init(&ctx, list);
	// exmdbc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	// if (!exmdbc_command_connection_is_selected(cmd))
	// 	exmdbc_command_abort(&cmd);
	// else {
	// 	exmdbc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_SELECT);
	// 	if ((capa & IMAPC_CAPABILITY_UNSELECT) != 0)
	// 		exmdbc_command_sendf(cmd, "UNSELECT");
	// 	else
	// 		exmdbc_command_sendf(cmd, "SELECT \"~~~\"");
	// 	exmdbc_simple_run(&ctx, &cmd);
	// }
	//
	// cmd = exmdbc_list_simple_context_init(&ctx, list);
	// exmdbc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	// exmdbc_command_sendf(cmd, "DELETE %s", exmdbc_list_storage_to_remote_name(list, name));
	// exmdbc_simple_run(&ctx, &cmd);
	//
	// if (fs_list != NULL && ctx.ret == 0) {
	// 	const char *fs_name = exmdbc_list_storage_to_fs_name(list, name);
	// 	(void)fs_list->v.delete_mailbox(fs_list, fs_name);
	// }
	return ctx.ret;
}

static int
exmdbc_list_delete_dir(struct mailbox_list *_list, const char *name)
{
	fprintf(stdout, "!!! exmdbc_list_delete_dir called\n");
	//TODO:EXMDBC:
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)_list;
	// struct mailbox_list *fs_list = exmdbc_list_get_fs(list);
	//
	// if (fs_list != NULL) {
	// 	const char *fs_name = exmdbc_list_storage_to_fs_name(list, name);
	// 	(void)mailbox_list_delete_dir(fs_list, fs_name);
	// }
	return 0;
}

static int
exmdbc_list_delete_symlink(struct mailbox_list *list,
			  const char *name ATTR_UNUSED)
{
	fprintf(stdout, "!!! exmdbc_list_delete_symlink called\n");
	mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE, "Not supported");
	return -1;
}

static int
exmdbc_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			  struct mailbox_list *newlist, const char *newname)
{
	fprintf(stdout, "!!! exmdbc_list_rename_mailbox called\n");
	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)oldlist;
	//TODO:EXMDBC:
	// struct mailbox_list *fs_list = exmdbc_list_get_fs(list);
	struct exmdbc_command *cmd;
	struct exmdbc_simple_context ctx;

	// if (oldlist != newlist) {
	// 	mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
	// 		"Can't rename mailboxes across storages.");
	// 	return -1;
	// }
	//
	// cmd = exmdbc_list_simple_context_init(&ctx, list);
	// exmdbc_command_sendf(cmd, "RENAME %s %s",
	// 			exmdbc_list_storage_to_remote_name(list, oldname),
	// 			exmdbc_list_storage_to_remote_name(list, newname));
	// exmdbc_simple_run(&ctx, &cmd);
	// if (ctx.ret == 0 && fs_list != NULL && oldlist == newlist) {
	// 	const char *old_fs_name =
	// 		exmdbc_list_storage_to_fs_name(list, oldname);
	// 	const char *new_fs_name =
	// 		exmdbc_list_storage_to_fs_name(list, newname);
	// 	(void)fs_list->v.rename_mailbox(fs_list, old_fs_name,
	// 					fs_list, new_fs_name);
	// }
	return ctx.ret;
}

struct mailbox_list exmdbc_mailbox_list = {
	.name = MAILBOX_LIST_NAME_EXMDBC,
	.props = MAILBOX_LIST_PROP_NO_LIST_INDEX,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	.v = {
		.alloc = exmdbc_list_alloc,
		.init = exmdbc_list_init,
		.deinit = exmdbc_list_deinit,
		.get_storage = mailbox_list_default_get_storage,
		.get_hierarchy_sep = exmdbc_list_get_hierarchy_sep,
		.get_vname = exmdbc_list_get_vname,
		.get_storage_name = exmdbc_list_get_storage_name,
		.get_path = exmdbc_list_get_path,
		.get_temp_prefix = exmdbc_list_get_temp_prefix,
		.join_refpattern = exmdbc_list_join_refpattern,
		.iter_init = exmdbc_list_iter_init,
		.iter_next = exmdbc_list_iter_next,
		.iter_deinit = exmdbc_list_iter_deinit,
		.subscriptions_refresh = exmdbc_list_subscriptions_refresh,
		.set_subscribed = exmdbc_list_set_subscribed,
		.delete_mailbox = exmdbc_list_delete_mailbox,
		.delete_dir = exmdbc_list_delete_dir,
		.delete_symlink = exmdbc_list_delete_symlink,
		.rename_mailbox = exmdbc_list_rename_mailbox,
	}
};
