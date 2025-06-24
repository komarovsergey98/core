#ifndef EXMDBC_MAILBOX_H
#define EXMDBC_MAILBOX_H

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "settings.h"
#include "mailbox-tree.h"
#include "exmdbc-msgmap.h"
#include "exmdbc-mail.h"
#include "exmdbc-list.h"
#include "exmdbc-search.h"
#include "exmdbc-storage.h"

/* Returns TRUE if we can assume from now on that untagged EXPUNGE, FETCH, etc.
   replies belong to this mailbox instead of to the previously selected
   mailbox. */
#define EXMDBC_MAILBOX_IS_FULLY_SELECTED(mbox) \
((mbox)->sync_uid_validity != 0)


void exmdbc_mailbox_run(struct exmdbc_mailbox *mbox);
void exmdbc_mailbox_run_nofetch(struct exmdbc_mailbox *mbox);
int exmdbc_mailbox_select(struct exmdbc_mailbox *mbox);
void exmdbc_mailbox_select_finish(struct exmdbc_mailbox *mbox);
bool exmdbc_mailbox_name_equals(struct exmdbc_mailbox *mbox, const char *remote_name);
void exmdbc_mailbox_noop(const struct exmdbc_mailbox *mbox);
void exmdbc_mailbox_set_corrupted(struct exmdbc_mailbox *mbox, const char *reason, ...) ATTR_FORMAT(2, 3);
const char *exmdbc_mailbox_get_remote_name(const struct exmdbc_mailbox *mbox);
struct mail_index_view * exmdbc_mailbox_get_sync_view(struct exmdbc_mailbox *mbox);
bool exmdbc_mailbox_fetch_state(struct exmdbc_mailbox *mbox, uint32_t first_uid);
bool exmdbc_mailbox_has_modseqs(struct exmdbc_mailbox *mbox);

#endif
