#ifndef EXMDBC_LIST_H
#define EXMDBC_LIST_H

#include "mailbox-list-private.h"

#define MAILBOX_LIST_NAME_EXMDBC "exmdbc"

struct exmdbc_mailbox_list {
	struct mailbox_list list;
	struct exmdbc_storage_client *client;
	struct mailbox_list *index_list;

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

#endif
