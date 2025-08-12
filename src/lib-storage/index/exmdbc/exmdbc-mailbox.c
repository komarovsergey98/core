#include "lib.h"
#include "ioloop.h"
#include "mail-index-modseq.h"
#include "exmdbc-mail.h"
#include "exmdbc-list.h"
#include "exmdbc-sync.h"
#include "exmdbc-storage.h"
#include "exmdbc-mailbox.h"

#include <stdio.h>


void exmdbc_mailbox_set_corrupted(struct exmdbc_mailbox *mbox,
				 const char *reason, ...)
{
	i_debug("[exmdbc] exmdbc_mailbox_set_corrupted called\n");
	const char *errmsg;
	va_list va;

	va_start(va, reason);
	errmsg = t_strdup_printf("Mailbox '%s' state corrupted: %s",
		mbox->box.name, t_strdup_vprintf(reason, va));
	va_end(va);

	mail_storage_set_internal_error(&mbox->storage->storage);

	if (!mbox->initial_sync_done) {
		/* we failed during initial sync. need to rebuild indexes if
		   we want to get this fixed */
		mail_index_mark_corrupted(mbox->box.index);
	} else {
		/* maybe the remote server is buggy and has become confused.
		   try reconnecting. */
	}
	//TODO:EXMDB: exmdbc_client_mailbox_reconnect(mbox->client_box, errmsg);
}

struct mail_index_view *
exmdbc_mailbox_get_sync_view(struct exmdbc_mailbox *mbox)
{
	i_debug("[exmdbc] exmdbc_mailbox_get_sync_view called\n");
	if (mbox->sync_view == NULL)
		mbox->sync_view = mail_index_view_open(mbox->box.index);
	return mbox->sync_view;
}

void exmdbc_mailbox_select_finish(struct exmdbc_mailbox *mbox)
{
	i_debug("[exmdbc] exmdbc_mailbox_select_finish called\n");
	if (mbox->exists_count == 0) {
		/* no mails. expunge everything. */
	} else {
		/* We don't know the latest flags, refresh them. */
		(void)exmdbc_mailbox_fetch_state(mbox, 1);
	}
	mbox->selected = TRUE;
	mbox->selecting = FALSE;
}

bool
exmdbc_mailbox_fetch_state(struct exmdbc_mailbox *mbox, uint32_t first_uid)
{
	i_debug("[exmdbc] exmdbc_mailbox_fetch_state called\n");

	if (mbox->exists_count == 0) {
		/* empty mailbox - no point in fetching anything.
		   just make sure everything is expunged in local index.
		   Delay calling imapc_mailbox_fetch_state_finish() until
		   SELECT finishes, so we see the updated UIDNEXT. */
		return FALSE;
	}
	if (mbox->state_fetching_uid1) {
		/* retrying after reconnection - don't send duplicate */
		return FALSE;
	}

	//TODO:EXMDBC: check mailbox modseq info retrived by dtos
	// if (imapc_mailbox_has_modseqs(mbox)) {
	// 	str_append(str, " MODSEQ");
	// 	mail_index_modseq_enable(mbox->box.index);
	// }

	mbox->state_fetching_uid1 = first_uid == 1;

	// if (index_mailbox_want_full_sync(&mbox->box, MAILBOX_SYNC_FLAG_FORCE_RESYNC))
		exmdbc_mailbox_sync(mbox);


	mbox->state_fetching_uid1 = FALSE;
	return TRUE;
}

bool exmdbc_mailbox_name_equals(struct exmdbc_mailbox *mbox,
			       const char *remote_name)
{
	i_debug("[exmdbc] exmdbc_mailbox_name_equals called\n");
	const char *exmdbc_remote_name =
		exmdbc_mailbox_get_remote_name(mbox);

	if (strcmp(exmdbc_remote_name, remote_name) == 0) {
		/* match */
		return TRUE;
	} else if (strcasecmp(mbox->box.name, "INBOX") == 0 &&
		   strcasecmp(remote_name, "INBOX") == 0) {
		/* case-insensitive INBOX */
		return TRUE;
	}
	return FALSE;
}

bool exmdbc_mailbox_has_modseqs(struct exmdbc_mailbox *mbox)
{
	i_debug("[exmdbc] exmdbc_mailbox_has_modseqs called\n");
	return FALSE; //TODO: EXMDBC:
}

void exmdbc_sync_uid_validity(struct exmdbc_mailbox *mbox)
{
	struct mail_index_view *view = mbox->box.view;
	struct mail_index_transaction *trans = mail_index_transaction_begin(view, 0);
	const struct mail_index_header *hdr = mail_index_get_header(view);

	if (hdr->uid_validity != mbox->sync_uid_validity && mbox->sync_uid_validity != 0) {
		if (hdr->uid_validity != 0) {
			mail_index_reset(trans);
		}
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&mbox->sync_uid_validity,
			sizeof(mbox->sync_uid_validity), TRUE);
	}

	mail_index_transaction_commit(&trans);
}