#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "mail-index-modseq.h"
#include "exmdbc-mail.h"
#include "exmdbc-msgmap.h"
#include "exmdbc-list.h"
#include "exmdbc-search.h"
#include "exmdbc-sync.h"
#include "exmdbc-storage.h"
#include "exmdbc-mailbox.h"

#include <exmdb_client_c.h>
#include <stdio.h>

#define NOTIFY_DELAY_MSECS 500

void exmdbc_mailbox_set_corrupted(struct exmdbc_mailbox *mbox,
				 const char *reason, ...)
{
	fprintf(stdout, "!!! exmdbc_mailbox_set_corrupted called\n");
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
	fprintf(stdout, "!!! exmdbc_mailbox_get_sync_view called\n");
	if (mbox->sync_view == NULL)
		mbox->sync_view = mail_index_view_open(mbox->box.index);
	return mbox->sync_view;
}

void exmdbc_mailbox_select_finish(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_select_finish called\n");
	if (mbox->exists_count == 0) {
		/* no mails. expunge everything. */
		mbox->sync_next_lseq = 1;
	} else {
		/* We don't know the latest flags, refresh them. */
		(void)exmdbc_mailbox_fetch_state(mbox, 1);
	}
	mbox->selected = TRUE;
}

bool
exmdbc_client_fetch_message_states(struct exmdbc_mailbox *mbox, uint32_t first_uid)
{
	fprintf(stdout, "!!! exmdbc_client_fetch_message_states called\n");
	unsigned int max_messages = 100;

	const char *username = mbox->box.list->ns->user->username;

	struct message_properties *messages = calloc(max_messages, sizeof(*messages));
	if (!messages) {
		fprintf(stderr, "Failed to allocate memory\n");
		return 1;
	}

	int count = exmdbc_client_get_folder_messages(mbox->storage->client->client, mbox->folder_id, messages,
		max_messages, username, first_uid);

	if (count < 0) {
		fprintf(stderr, "Failed to get folder messages\n");
		free(messages);
		return 1;
	}

	printf("Got %d messages from folder %" PRIu64 "\n", count, mbox->folder_id);
	for (int i = 0; i < count; ++i) {
		printf("Message %" PRIu64 ": Subject='%s', From='%s', To='%s', Timestamp=%" PRIu64 "\n",
			messages[i].mid,
			messages[i].subject ? messages[i].subject : "(null)",
			messages[i].from_name ? messages[i].from_name : "(null)",
			messages[i].to_name ? messages[i].to_name : "(null)",
			messages[i].delivery_time);
		// Пам'ятай звільняти strdup'ed рядки, якщо потрібно
		free((void*)messages[i].subject);
		free((void*)messages[i].from_name);
		free((void*)messages[i].to_name);
		free((void*)messages[i].body_plain);
		free((void*)messages[i].body_html);
	}

	free(messages);
	return 0;

}

bool
exmdbc_mailbox_fetch_state(struct exmdbc_mailbox *mbox, uint32_t first_uid)
{
	fprintf(stdout, "!!! exmdbc_mailbox_fetch_state called\n");


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

	//TODO:EXMDBC: ask jan for GMAIL features support
	// if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_GMAIL_MIGRATION)) {
	// 	enum mailbox_info_flags flags;
	//
	// 	if (!mail_index_is_in_memory(mbox->box.index)) {
	// 		/* these can be efficiently fetched among flags and
	// 		   stored into cache */
	// 		str_append(str, " X-GM-MSGID");
	// 	}
	// 	/* do this only for the \All mailbox */
	// 	if (imapc_list_get_mailbox_flags(mbox->box.list,
	// 					 mbox->box.name, &flags) == 0 &&
	// 		(flags & MAILBOX_SPECIALUSE_ALL) != 0)
	// 		str_append(str, " X-GM-LABELS");
	//
	// }

	if (first_uid == 1) {
		mbox->sync_next_lseq = 1;
		mbox->sync_next_rseq = 1;
		mbox->state_fetched_success = FALSE;
	}
	mbox->state_fetching_uid1 = first_uid == 1;

	//TODO:EXMDBC do fetch from GromoxRPC
	// exmdbc_client_fetch_message_states(mbox, first_uid);
	exmdbc_mailbox_sync(mbox);

	mbox->state_fetching_uid1 = FALSE;
	return TRUE;
}

static bool keywords_are_equal(struct mail_keywords *kw,
			       const ARRAY_TYPE(keyword_indexes) *kw_arr)
{

	fprintf(stdout, "!!! keywords_are_equal called\n");

	return FALSE;
}

bool exmdbc_mailbox_name_equals(struct exmdbc_mailbox *mbox,
			       const char *remote_name)
{
	fprintf(stdout, "!!! exmdbc_mailbox_name_equals called\n");
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

void exmdbc_mailbox_run_nofetch(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_run_nofetch called\n");
	do {
		//TODO:EXMDBC
		//exmdbc_client_run(mbox->storage->client->client);
	} while (mbox->storage->reopen_count > 0 ||
		 mbox->state_fetching_uid1);
}

bool exmdbc_mailbox_has_modseqs(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_has_modseqs called\n");
	return FALSE; //TODO: EXMDBC:
}

