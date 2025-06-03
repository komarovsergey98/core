#ifndef EXMDBC_LIST_H
#define EXMDBC_LIST_H

#include "mailbox-list-private.h"

#define MAILBOX_LIST_NAME_EXMDBC "exmdbc"

#define MAX_MAILBOXES 128


struct exmdbc_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_info mailboxes[MAX_MAILBOXES];
	unsigned int mailbox_count;
	unsigned int next_index;
};

struct exmdbc_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_tree_context *tree;
	struct mailbox_node *ns_root;

	struct exmdbc_list_iterate_context list_ctx;
	struct mailbox_tree_iterate_context *iter;
	struct mailbox_info info;
	string_t *special_use;
};

struct exmdbc_mailbox_list {
	struct mailbox_list list;
	struct exmdbc_storage_client *client;
	struct mailbox_list *index_list;
	struct settings_instance *index_list_set_instance;

	HASH_TABLE(const char *, void *) folder_id_map;


	bool folder_map_initialized;

	struct mailbox_tree_context *mailboxes, *tmp_subscriptions;
	char root_sep;
	time_t last_refreshed_mailboxes;

	unsigned int iter_count;

	bool refreshed_subscriptions:1;
	bool refreshed_mailboxes:1;
	bool refreshed_mailboxes_recently:1;
	bool index_list_failed:1;
	bool root_sep_pending:1;
};

extern struct mailbox_list exmdbc_mailbox_list;

int exmdbc_list_refresh(struct exmdbc_mailbox_list *list, struct exmdbc_mailbox_list_iterate_context *ctx);

#endif
