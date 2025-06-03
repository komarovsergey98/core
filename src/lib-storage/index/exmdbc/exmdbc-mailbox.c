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


static void exmdbc_mailbox_init_delayed_trans(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_init_delayed_trans called\n");
	if (mbox->delayed_sync_trans != NULL)
		return;

	i_assert(mbox->delayed_sync_cache_view == NULL);
	i_assert(mbox->delayed_sync_cache_trans == NULL);

	mbox->delayed_sync_trans =
		mail_index_transaction_begin(exmdbc_mailbox_get_sync_view(mbox),
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mbox->delayed_sync_view =
		mail_index_transaction_open_updated_view(mbox->delayed_sync_trans);

	mbox->delayed_sync_cache_view =
		mail_cache_view_open(mbox->box.cache, mbox->delayed_sync_view);
	mbox->delayed_sync_cache_trans =
		mail_cache_get_transaction(mbox->delayed_sync_cache_view,
					   mbox->delayed_sync_trans);
}

static int exmdbc_mailbox_commit_delayed_expunges(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_commit_delayed_expunges called\n");
	struct mail_index_view *view = exmdbc_mailbox_get_sync_view(mbox);
	struct mail_index_transaction *trans;
	struct seq_range_iter iter;
	unsigned int n;
	uint32_t lseq, uid;
	int ret;

	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);

	seq_range_array_iter_init(&iter, &mbox->delayed_expunged_uids); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		if (mail_index_lookup_seq(view, uid, &lseq))
			mail_index_expunge(trans, lseq);
	}
	array_clear(&mbox->delayed_expunged_uids);
	ret = mail_index_transaction_commit(&trans);
	if (ret < 0)
		mailbox_set_index_error(&mbox->box);
	return ret;
}

int exmdbc_mailbox_commit_delayed_trans(struct exmdbc_mailbox *mbox,
				       bool force, bool *changes_r)
{
	fprintf(stdout, "!!! exmdbc_mailbox_commit_delayed_trans called\n");
	int ret = 0;

	*changes_r = FALSE;

	if (mbox->delayed_sync_view != NULL)
		mail_index_view_close(&mbox->delayed_sync_view);
	if (mbox->delayed_sync_trans == NULL)
		;
	else if (!mbox->selected && !force) {
		/* ignore any changes done during SELECT */
		mail_index_transaction_rollback(&mbox->delayed_sync_trans);
	} else {
		if (mail_index_transaction_commit(&mbox->delayed_sync_trans) < 0) {
			mailbox_set_index_error(&mbox->box);
			ret = -1;
		}
		*changes_r = TRUE;
	}
	mbox->delayed_sync_cache_trans = NULL;
	if (mbox->delayed_sync_cache_view != NULL)
		mail_cache_view_close(&mbox->delayed_sync_cache_view);

	if (array_count(&mbox->delayed_expunged_uids) > 0) {
		/* delayed expunges - commit them now in a separate
		   transaction. Reopen mbox->sync_view to see changes
		   committed in delayed_sync_trans. */
		if (mbox->sync_view != NULL)
			mail_index_view_close(&mbox->sync_view);
		if (exmdbc_mailbox_commit_delayed_expunges(mbox) < 0)
			ret = -1;
	}

	if (mbox->sync_view != NULL)
		mail_index_view_close(&mbox->sync_view);
	i_assert(mbox->delayed_sync_trans == NULL);
	i_assert(mbox->delayed_sync_view == NULL);
	i_assert(mbox->delayed_sync_cache_trans == NULL);
	return ret;
}

static void
exmdbc_mailbox_index_expunge(struct exmdbc_mailbox *mbox, uint32_t uid)
{
	fprintf(stdout, "!!! exmdbc_mailbox_index_expunge called\n");
	uint32_t lseq;

	if (mail_index_lookup_seq(mbox->sync_view, uid, &lseq))
		mail_index_expunge(mbox->delayed_sync_trans, lseq);
	else if (mail_index_lookup_seq(mbox->delayed_sync_view, uid, &lseq)) {
		/* this message exists only in this transaction. lib-index
		   can't currently handle expunging anything except the last
		   appended message in a transaction, and fixing it would be
		   quite a lot of trouble. so instead we'll just delay doing
		   this expunge until after the current transaction has been
		   committed. */
		seq_range_array_add(&mbox->delayed_expunged_uids, uid);
	} else {
		/* already expunged by another session */
	}
}

static void
exmdbc_mailbox_fetch_state_finish(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_fetch_state_finish called\n");
	uint32_t lseq, uid, msg_count;

	if (mbox->sync_next_lseq == 0) {
		/* FETCH n:*, not 1:* */
		i_assert(mbox->state_fetched_success ||
			 (mbox->box.flags & MAILBOX_FLAG_SAVEONLY) != 0);
		return;
	}

	/* if we haven't seen FETCH reply for some messages at the end of
	   mailbox they've been externally expunged. */
	msg_count = mail_index_view_get_messages_count(mbox->delayed_sync_view);
	for (lseq = mbox->sync_next_lseq; lseq <= msg_count; lseq++) {
		mail_index_lookup_uid(mbox->delayed_sync_view, lseq, &uid);
		if (uid >= mbox->sync_uid_next) {
			/* another process already added new messages to index
			   that our IMAP connection hasn't seen yet */
			break;
		}
		exmdbc_mailbox_index_expunge(mbox, uid);
	}

	mbox->sync_next_lseq = 0;
	mbox->sync_next_rseq = 0;
	mbox->state_fetched_success = TRUE;
}

void exmdbc_mailbox_select_finish(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_select_finish called\n");
	if (mbox->exists_count == 0) {
		/* no mails. expunge everything. */
		mbox->sync_next_lseq = 1;
		exmdbc_mailbox_init_delayed_trans(mbox);
		exmdbc_mailbox_fetch_state_finish(mbox);
	} else {
		/* We don't know the latest flags, refresh them. */
		(void)exmdbc_mailbox_fetch_state(mbox, 1);
	}
	mbox->selected = TRUE;
}

bool
exmdbc_mailbox_fetch_state(struct exmdbc_mailbox *mbox, uint32_t first_uid)
{
	// fprintf(stdout, "!!! exmdbc_mailbox_fetch_state called\n");
	//
	// if (mbox->exists_count == 0) {
	// 	/* empty mailbox - no point in fetching anything.
	// 	   just make sure everything is expunged in local index.
	// 	   Delay calling imapc_mailbox_fetch_state_finish() until
	// 	   SELECT finishes, so we see the updated UIDNEXT. */
	// 	return FALSE;
	// }
	// if (mbox->state_fetching_uid1) {
	// 	/* retrying after reconnection - don't send duplicate */
	// 	return FALSE;
	// }
	//
	// string_t *str = t_str_new(64);
	// str_printfa(str, "UID FETCH %u:* (FLAGS", first_uid);
	// if (exmdbc_mailbox_has_modseqs(mbox)) {
	// 	str_append(str, " MODSEQ");
	// 	mail_index_modseq_enable(mbox->box.index);
	// }
	// str_append_c(str, ')');
	//
	// cmd = imapc_client_mailbox_cmd(mbox->client_box,
	// 	imapc_mailbox_fetch_state_callback, mbox);
	// if (first_uid == 1) {
	// 	mbox->sync_next_lseq = 1;
	// 	mbox->sync_next_rseq = 1;
	// 	mbox->state_fetched_success = FALSE;
	// 	/* only the FETCH 1:* is retriable - others will be retried
	// 	   by the 1:* after the reconnection */
	// 	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	// }
	// mbox->state_fetching_uid1 = first_uid == 1;
	// imapc_command_send(cmd, str_c(str));
	// return TRUE;
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

void exmdbc_untagged_fetch_ctx_free(struct exmdbc_untagged_fetch_ctx **_ctx)
{
	fprintf(stdout, "!!! exmdbc_untagged_fetch_ctx_free called\n");
	struct exmdbc_untagged_fetch_ctx *ctx = *_ctx;

	*_ctx = NULL;
	i_assert(ctx != NULL);

	pool_unref(&ctx->pool);
}

void exmdbc_untagged_fetch_update_flags(struct exmdbc_mailbox *mbox,
				       struct exmdbc_untagged_fetch_ctx *ctx,
				       struct mail_index_view *view,
				       uint32_t lseq)
{
	fprintf(stdout, "!!! exmdbc_untagged_fetch_update_flags called\n");
	ARRAY_TYPE(keyword_indexes) old_kws;
	struct mail_keywords *kw;
	const struct mail_index_record *rec = NULL;
	const char *atom;

	if (!ctx->have_flags)
		return;

	rec = mail_index_lookup(view, lseq);
	if (rec->flags != ctx->flags) {
		mail_index_update_flags(mbox->delayed_sync_trans, lseq,
					MODIFY_REPLACE, ctx->flags);
	}

	t_array_init(&old_kws, 8);
	mail_index_lookup_keywords(view, lseq, &old_kws);

	if (ctx->have_gmail_labels) {
		/* add keyword for mails that have GMail labels.
		   this can be used for "All Mail" mailbox migrations
		   with dsync */
		atom = "$GMailHaveLabels";
		array_push_back(&ctx->keywords, &atom);
	}

	array_append_zero(&ctx->keywords);
	kw = mail_index_keywords_create(mbox->box.index,
					array_front(&ctx->keywords));
	if (!keywords_are_equal(kw, &old_kws)) {
		mail_index_update_keywords(mbox->delayed_sync_trans,
					   lseq, MODIFY_REPLACE, kw);
	}
	mail_index_keywords_unref(&kw);
}

void exmdbc_mailbox_register_untagged(struct exmdbc_mailbox *mbox,
				     const char *key,
				     exmdbc_mailbox_callback_t *callback)
{
	fprintf(stdout, "!!! exmdbc_mailbox_register_untagged called\n");
	struct exmdbc_mailbox_event_callback *cb;

	cb = array_append_space(&mbox->untagged_callbacks);
	cb->name = p_strdup(mbox->box.pool, key);
	cb->callback = callback;
}

void exmdbc_mailbox_register_resp_text(struct exmdbc_mailbox *mbox,
				      const char *key,
				      exmdbc_mailbox_callback_t *callback)
{
	fprintf(stdout, "!!! exmdbc_mailbox_register_resp_text called\n");
	struct exmdbc_mailbox_event_callback *cb;

	cb = array_append_space(&mbox->resp_text_callbacks);
	cb->name = p_strdup(mbox->box.pool, key);
	cb->callback = callback;
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

void exmdbc_mailbox_register_callbacks(struct exmdbc_mailbox *mbox)
{
	//Remove this in the end. We are not using imapc_client and not sending cmds anymore so we don't need untagged reply more
	// fprintf(stdout, "!!! exmdbc_mailbox_register_callbacks called\n");
	// exmdbc_mailbox_register_untagged(mbox, "EXISTS",
	// 				exmdbc_untagged_exists);
	// exmdbc_mailbox_register_untagged(mbox, "FETCH",
	// 				exmdbc_untagged_fetch);
	// exmdbc_mailbox_register_untagged(mbox, "EXPUNGE",
	// 				exmdbc_untagged_expunge);
	// exmdbc_mailbox_register_untagged(mbox, "SEARCH",
	// 				exmdbc_untagged_search);
	// exmdbc_mailbox_register_untagged(mbox, "ESEARCH",
	// 				exmdbc_untagged_esearch);
	// exmdbc_mailbox_register_resp_text(mbox, "UIDVALIDITY",
	// 				 exmdbc_resp_text_uidvalidity);
	// exmdbc_mailbox_register_resp_text(mbox, "UIDNEXT",
	// 				 exmdbc_resp_text_uidnext);
	// exmdbc_mailbox_register_resp_text(mbox, "HIGHESTMODSEQ",
	// 				 exmdbc_resp_text_highestmodseq);
	// exmdbc_mailbox_register_resp_text(mbox, "PERMANENTFLAGS",
	// 				 exmdbc_resp_text_permanentflags);
}

