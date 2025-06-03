#include "lib.h"
#include "mailbox-list-private.h"
#include "exmdbc-list.h"

#include <dsasl-client.h>
#include <exmdbc-storage.h>
#include <exmdbc-settings.h>
#include <hash.h>
#include <ioloop.h>
#include <settings.h>
#include <stdio.h>
#include <str.h>
#include <src/lib-imap-client/imapc-client.h>
#include <src/lib-imap-client/imapc-settings.h>

#include "mail-storage-service.h"
#include "mailbox-tree.h"
#include "mailbox-list-subscriptions.h"
#include "exmdb_client_c.h"

#define DNS_CLIENT_SOCKET_NAME "dns-client"


int exmdbc_list_fill_mailbox_info(struct exmdbc_mailbox_list *list, struct exmdbc_mailbox_list_iterate_context *ctx)
{
	struct exmdbc_folder_dto tmp_array[128];
	unsigned int tmp_count = 0;

	const char *username = list->list.ns->user->username;
	if (exmdbc_client_get_folders_dtos(list->client->client, tmp_array, username, MAX_MAILBOXES, &tmp_count) < 0)
		return -1;

	ctx->list_ctx.mailbox_count = 0;

	for (unsigned int i = 0; i < tmp_count && ctx->list_ctx.mailbox_count < MAX_MAILBOXES; ++i) {
		struct mailbox_info *info = &ctx->list_ctx.mailboxes[ctx->list_ctx.mailbox_count++];
		memset(info, 0, sizeof(*info));

		info->vname = p_strdup(ctx->ctx.pool, tmp_array[i].name);
		info->flags = MAILBOX_NOSELECT;
		info->ns = ctx->ctx.list->ns;
		const char *lower_vname = str_lcase(p_strdup(ctx->ctx.pool, tmp_array[i].name));
		hash_table_insert(list->folder_id_map,
			lower_vname,
			POINTER_CAST(tmp_array[i].folder_id));

	}
	list->folder_map_initialized = true;
	return 0;
}

const char *
exmdbc_list_storage_to_remote_name(struct exmdbc_mailbox_list *list,
				  const char *storage_name)
{
	return mailbox_list_unescape_name_params(storage_name, "",
		list->root_sep, mailbox_list_get_hierarchy_sep(&list->list),
		list->list.mail_set->mailbox_list_storage_escape_char[0]);
}

int exmdbc_list_try_get_root_sep(struct exmdbc_mailbox_list * list, char * sep);

static const char *
exmdbc_list_remote_to_storage_name(struct exmdbc_mailbox_list *list,
				  const char *remote_name)
{
	/* typically mailbox_list_escape_name() is used to escape vname into
	   a list name. but we want to convert remote IMAP name to a list name,
	   so we need to use the remote IMAP separator. */
	return mailbox_list_escape_name_params(remote_name, "",
		list->root_sep,
		mailbox_list_get_hierarchy_sep(&list->list),
		list->list.mail_set->mailbox_list_storage_escape_char[0], "");
}

int exmdbc_list_refresh(struct exmdbc_mailbox_list *list, struct exmdbc_mailbox_list_iterate_context *ctx) {
	fprintf(stdout, "!!! exmdbc_list_refresh called\n");

	// struct mailbox_node *node;
	// const char *pattern;
	char sep;

	//TODO: EXMDBC
	// if (exmdbc_list_try_get_root_sep(list, &sep) < 0)
	// 	return -1;
	if (list->refreshed_mailboxes)
		return 0;
	fprintf(stderr, "refresh for namespace: '%s'\n", list->list.ns->prefix);
	if ((list->list.ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		list->refreshed_mailboxes = TRUE;
		list->refreshed_mailboxes_recently = TRUE;
		return 0;
	}

	//TODO: EXMDBC
	// if (*list->set->imapc_list_prefix == '\0')
	// 	pattern = "*";
	// else {
	// 	/* list "prefix*" instead of "prefix.*". this may return a bit
	// 	   more than we want, but we're also interested in the flags
	// 	   of the prefix itself. */
	// 	pattern = t_strdup_printf("%s*", list->set->imapc_list_prefix);
	// }

	//cmd = imapc_list_simple_context_init(&ctx, list);
	//imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	//imapc_command_sendf(cmd, "LIST \"\" %s", pattern);
	mailbox_tree_deinit(&list->mailboxes);
	list->mailboxes = mailbox_tree_init(mail_namespace_get_sep(list->list.ns));
	mailbox_tree_set_parents_nonexistent(list->mailboxes);
	//imapc_simple_run(&ctx, &cmd);

	// if ((list->list.ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
	// 	/* INBOX always exists in IMAP server. since this namespace is
	// 	   marked with inbox=yes, show the INBOX even if
	// 	   imapc_list_prefix doesn't match it */
	// 	bool created;
	// 	node = mailbox_tree_get(list->mailboxes, "INBOX", &created);
	// 	if (*list->set->imapc_list_prefix != '\0') {
	// 		/* this listing didn't include the INBOX itself, but
	// 		   might have included its children. make sure there
	// 		   aren't any extra flags in it (especially
	// 		   \NonExistent) */
	// 		node->flags &= MAILBOX_CHILDREN;
	// 	}
	// }
	unsigned int count = 0;
	if (exmdbc_list_fill_mailbox_info(list, ctx) < 0)
		return -1;
	ctx->list_ctx.mailbox_count = count;
	list->refreshed_mailboxes = TRUE;
	list->refreshed_mailboxes_recently = TRUE;
	list->last_refreshed_mailboxes = ioloop_time;
	//TODO: EXMDBC
	// exmdbc_list_delete_unused_indexes(list);

	return 0;


	// //---------------------------------
	// unsigned int count = 0;
	//
	// const char *user = list->list.ns->user->username;
	// mailbox_tree_deinit(&list->mailboxes);
	// list->mailboxes = mailbox_tree_init(mail_namespace_get_sep(list->list.ns));
	// mailbox_tree_set_parents_nonexistent(list->mailboxes);
	//
	// if (exmdbc_list_fill_mailbox_info(ctx->ctx.pool, list->client->client, user, ctx->mailboxes, MAX_MAILBOXES, &count) < 0)
	// 	return -1;
	//
	// ctx->mailbox_count = count;
}


static void
exmdbc_list_build_match_tree(struct exmdbc_mailbox_list_iterate_context *ctx)
{
	struct exmdbc_mailbox_list *list =
		(struct exmdbc_mailbox_list *)ctx->ctx.list;
	struct mailbox_list_iter_update_context update_ctx;
	struct mailbox_tree_iterate_context *iter;
	struct mailbox_node *node;
	const char *vname;

	i_zero(&update_ctx);
	update_ctx.iter_ctx = &ctx->ctx;
	update_ctx.tree_ctx = ctx->tree;
	update_ctx.glob = ctx->ctx.glob;
	update_ctx.match_parents = TRUE;

	iter = mailbox_tree_iterate_init(list->mailboxes, NULL, 0);
	while ((node = mailbox_tree_iterate_next(iter, &vname)) != NULL) {
		update_ctx.leaf_flags = node->flags;
		mailbox_list_iter_update(&update_ctx, vname);
	}
	mailbox_tree_iterate_deinit(&iter);
}

struct mailbox_list_iterate_context *
exmdbc_list_iter_init(struct mailbox_list *_list, const char *const *patterns,
                      enum mailbox_list_iter_flags flags) {
	fprintf(stdout, "!!! exmdbc_list_iter_init called\n");

	struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)_list;
	struct mailbox_list_iterate_context *_ctx;
	struct exmdbc_mailbox_list_iterate_context *ctx;
	pool_t pool;
	const char *ns_root_name;
	char ns_sep;
	int ret = 0;

	pool = pool_alloconly_create("mailbox list exmdbc iter", 2048);
	ctx = p_new(pool, struct exmdbc_mailbox_list_iterate_context, 1);
	ctx->ctx.pool = pool;
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->list_ctx.next_index = 0;
	array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);


	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 ||
		(flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0)
		ret = exmdbc_list_refresh(list, ctx);

	list->iter_count++;

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* we're listing only subscriptions. just use the cached
		   subscriptions list. */
		_ctx = mailbox_list_subscriptions_iter_init(_list, patterns,
								flags);
		if (ret < 0)
			_ctx->failed = TRUE;
		return _ctx;
	}
	/* if we've already failed, make sure we don't call
	   mailbox_list_get_hierarchy_sep(), since it clears the error */
	ns_sep = ret < 0 ? '/' : mail_namespace_get_sep(_list->ns);

	//TODO: EXMDBC
	//ctx->ctx.glob = imap_match_init_multiple(pool, patterns, FALSE, ns_sep);
	array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);

	ctx->info.ns = _list->ns;

	ctx->tree = mailbox_tree_init(ns_sep);
	mailbox_tree_set_parents_nonexistent(ctx->tree);
	if (ret == 0)
		exmdbc_list_build_match_tree(ctx);

	if (list->list.ns->prefix_len > 0) {
		ns_root_name = t_strndup(_list->ns->prefix,
					 _list->ns->prefix_len - 1);
		ctx->ns_root = mailbox_tree_lookup(ctx->tree, ns_root_name);
	}

	ctx->iter = mailbox_tree_iterate_init(ctx->tree, NULL, 0);
	if (ret < 0)
		ctx->ctx.failed = TRUE;
	return &ctx->ctx;
}

static void
exmdbc_list_write_special_use(struct exmdbc_mailbox_list_iterate_context *ctx,
				 struct mailbox_node *node)
{
	unsigned int i;

	if (ctx->special_use == NULL)
		ctx->special_use = str_new(ctx->ctx.pool, 64);
	str_truncate(ctx->special_use, 0);

	//TODO: EXMDBC
	// for (i = 0; i < N_ELEMENTS(imap_list_flags); i++) {
	// 	if ((node->flags & imap_list_flags[i].flag) != 0 &&
	// 		(node->flags & MAILBOX_SPECIALUSE_MASK) != 0) {
	// 		str_append(ctx->special_use, imap_list_flags[i].str);
	// 		str_append_c(ctx->special_use, ' ');
	// 		}
	// }

	if (str_len(ctx->special_use) > 0) {
		str_truncate(ctx->special_use, str_len(ctx->special_use) - 1);
		ctx->info.special_use = str_c(ctx->special_use);
	} else {
		ctx->info.special_use = NULL;
	}
}

static bool
exmdbc_list_is_ns_root(struct exmdbc_mailbox_list_iterate_context *ctx,
			  struct mailbox_node *node)
{
	struct mailbox_node *root_node = ctx->ns_root;

	while (root_node != NULL) {
		if (node == root_node)
			return TRUE;
		root_node = root_node->parent;
	}
	return FALSE;
}

const struct mailbox_info *
exmdbc_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_list_iter_next called\n");

	struct exmdbc_mailbox_list_iterate_context *ctx =
		(struct exmdbc_mailbox_list_iterate_context *)_ctx;

	struct exmdbc_list_iterate_context *lc = &ctx->list_ctx;

	if (_ctx->failed)
		return NULL;

	if (lc->next_index >= lc->mailbox_count)
		return NULL;

	return &lc->mailboxes[lc->next_index++];

	// struct exmdbc_mailbox_list_iterate_context *ctx =
	// 		(struct exmdbc_mailbox_list_iterate_context *)_ctx;
	// struct exmdbc_mailbox_list *list =
	// 	(struct exmdbc_mailbox_list *)_ctx->list;
	// struct mailbox_node *node;
	// const char *vname;
	//
	// if (_ctx->failed)
	// 	return NULL;
	//
	// if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
	// 	return mailbox_list_subscriptions_iter_next(_ctx);
	//
	// do {
	// 	node = mailbox_tree_iterate_next(ctx->iter, &vname);
	// 	if (node == NULL)
	// 		return mailbox_list_iter_default_next(_ctx);
	// } while ((node->flags & MAILBOX_MATCHED) == 0 ||
	// 	 (exmdbc_list_is_ns_root(ctx, node) &&
	// 	  (strcasecmp(vname, "INBOX") != 0 ||
	// 	   (ctx->info.ns->flags & NAMESPACE_FLAG_INBOX_ANY) == 0)));
	//
	// if (ctx->info.ns->prefix_len > 0 &&
	// 	strcasecmp(vname, "INBOX") != 0 &&
	// 	strncmp(vname, ctx->info.ns->prefix, ctx->info.ns->prefix_len-1) == 0 &&
	// 	vname[ctx->info.ns->prefix_len] == '\0') {
	// 	/* don't return "" name */
	// 	return exmdbc_list_iter_next(_ctx);
	// 	}
	//
	// ctx->info.vname = vname;
	// ctx->info.flags = node->flags;
	// if ((_ctx->list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
	// 	/* we're iterating the INBOX namespace. pass through the
	// 	   SPECIAL-USE flags if they exist. */
	// 	exmdbc_list_write_special_use(ctx, node);
	// } else {
	// 	ctx->info.special_use = NULL;
	// }
	// return &ctx->info;
}

int exmdbc_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_list_iter_deinit called\n");
	struct exmdbc_mailbox_list_iterate_context *ctx =
		(struct exmdbc_mailbox_list_iterate_context *)_ctx;
	struct exmdbc_mailbox_list *list =
		(struct exmdbc_mailbox_list *)_ctx->list;
	int ret = _ctx->failed ? -1 : 0;

	i_assert(list->iter_count > 0);

	if (--list->iter_count == 0) {
		list->refreshed_mailboxes = FALSE;
		list->refreshed_subscriptions = FALSE;
	}

	if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		return mailbox_list_subscriptions_iter_deinit(_ctx);

	mailbox_tree_iterate_deinit(&ctx->iter);
	mailbox_tree_deinit(&ctx->tree);
	pool_unref(&_ctx->pool);
	return ret;
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
	hash_table_create(&list->folder_id_map, pool, 0, str_hash, strcmp);

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
		return -1;
	}
	*sep_r = list->root_sep;
	return 0;
}

char exmdbc_list_get_hierarchy_sep(struct mailbox_list * _list)
{
	fprintf(stdout, "!!! exmdbc_list_get_hierarchy_sep called\n");
	return '/';
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
