/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include <exmdbc-mailbox.h>
#include <stdio.h>

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "mail-copy.h"
#include "mailbox-list-private.h"
#include "exmdbc-msgmap.h"
#include "exmdbc-storage.h"
#include "seq-set-builder.h"

struct exmdbc_save_context {
	struct mail_save_context ctx;

	struct exmdbc_mailbox *mbox;
	struct exmdbc_mailbox *src_mbox;
	struct mail_index_transaction *trans;

	int fd;
	char *temp_path;
	struct istream *input;

	uint32_t dest_uid_validity;
	ARRAY_TYPE(seq_range) dest_saved_uids;
	unsigned int save_count;

	bool failed:1;
	bool finished:1;
};

struct exmdbc_save_cmd_context {
	struct exmdbc_save_context *ctx;
	int ret;
};

#define EXMDBC_SAVECTX(s)	container_of(s, struct exmdbc_save_context, ctx)
#define EXMDBC_SERVER_CMDLINE_MAX_LEN 	8000

void exmdbc_transaction_save_rollback(struct mail_save_context *_ctx);

struct mail_save_context *
exmdbc_save_alloc(struct mailbox_transaction_context *t)
{
	fprintf(stdout, "!!! exmdbc_save_alloc called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(t->box);
	struct exmdbc_save_context *ctx;

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL) {
		ctx = i_new(struct exmdbc_save_context, 1);
		ctx->ctx.transaction = t;
		ctx->mbox = mbox;
		ctx->src_mbox = NULL;
		ctx->trans = t->itrans;
		ctx->fd = -1;
		t->save_ctx = &ctx->ctx;
	}
	return t->save_ctx;
}

int exmdbc_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	fprintf(stdout, "!!! exmdbc_save_begin called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);
	const char *path;

	i_assert(ctx->fd == -1);

	//TODO:EXMDBC:
	//ctx->fd = exmdbc_client_create_temp_fd(ctx->mbox->storage->client->client,
	//				      &path);
	if (ctx->fd == -1) {
		mail_set_critical(_ctx->dest_mail,
				  "Couldn't create temp file %s", path);
		ctx->failed = TRUE;
		return -1;
	}
	/* we may not know the size of the input, or be sure that it contains
	   only CRLFs. so we'll always first write the mail to a temp file and
	   upload it from there to remote server. */
	ctx->finished = FALSE;
	ctx->temp_path = i_strdup(path);
	ctx->input = i_stream_create_crlf(input);
	_ctx->data.output = o_stream_create_fd_file(ctx->fd, 0, FALSE);
	o_stream_cork(_ctx->data.output);
	return 0;
}

int exmdbc_save_continue(struct mail_save_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_save_continue called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);

	if (ctx->failed)
		return -1;

	if (index_storage_save_continue(_ctx, ctx->input, NULL) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

static void
exmdbc_append_keywords(string_t *str, struct mail_keywords *kw)
{
	fprintf(stdout, "!!! exmdbc_append_keywords called\n");
	const ARRAY_TYPE(keywords) *kw_arr;
	const char *kw_str;
	unsigned int i;

	kw_arr = mail_index_get_keywords(kw->index);
	for (i = 0; i < kw->count; i++) {
		kw_str = array_idx_elem(kw_arr, kw->idx[i]);
		if (str_len(str) > 1)
			str_append_c(str, ' ');
		str_append(str, kw_str);
	}
}

static int exmdbc_save_append(struct exmdbc_save_context *ctx)
{
	fprintf(stdout, "!!! exmdbc_save_append called\n");
	struct mail_save_context *_ctx = &ctx->ctx;
	struct mail_save_data *mdata = &_ctx->data;
	struct exmdbc_command *cmd;
	struct exmdbc_save_cmd_context sctx;
	struct istream *input;
	const char *flags = "", *internaldate = "";

	if (mdata->flags != 0 || mdata->keywords != NULL) {
		string_t *str = t_str_new(64);

		str_append(str, " (");

	//TODO:EXMDBC:
	//imap_write_flags(str, mdata->flags & ENUM_NEGATE(MAIL_RECENT), NULL);
		if (mdata->keywords != NULL)
			exmdbc_append_keywords(str, mdata->keywords);
		str_append_c(str, ')');
		flags = str_c(str);
	}
	if (mdata->received_date != (time_t)-1) {

		//TODO:EXMDBC:
		// internaldate = t_strdup_printf(" \"%s\"",
		// imap_to_datetime(mdata->received_date));
	}

	ctx->mbox->exists_received = FALSE;

	input = i_stream_create_fd(ctx->fd, IO_BLOCK_SIZE);
	sctx.ctx = ctx;
	sctx.ret = -2;

	//TODO:EXMDBC:
	//cmd = exmdbc_client_cmd(ctx->mbox->storage->client->client, exmdbc_save_callback, &sctx);
	//exmdbc_command_sendf(cmd, "APPEND %s%1s%1s %p",
	//	exmdbc_mailbox_get_remote_name(ctx->mbox),
	//	flags, internaldate, input);
	i_stream_unref(&input);
	while (sctx.ret == -2)
		exmdbc_mailbox_run(ctx->mbox);

	if (sctx.ret == 0 && ctx->mbox->selected &&
	    !ctx->mbox->exists_received) {
		/* e.g. Courier doesn't send EXISTS reply before the tagged
		   APPEND reply. That isn't exactly required by the IMAP RFC,
		   but it makes the behavior better. See if NOOP finds
		   the mail. */
		sctx.ret = -2;
		/*cmd = exmdbc_client_cmd(ctx->mbox->storage->client->client,
				       exmdbc_save_noop_callback, &sctx);
		exmdbc_command_set_flags(cmd, EXMDBC_COMMAND_FLAG_RETRIABLE);
		exmdbc_command_send(cmd, "NOOP");*/
		while (sctx.ret == -2)
			exmdbc_mailbox_run(ctx->mbox);
	}
	return sctx.ret;
}

int exmdbc_save_finish(struct mail_save_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_save_finish called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);
	struct mail_storage *storage = _ctx->transaction->box->storage;

	ctx->finished = TRUE;

	if (!ctx->failed) {
		if (o_stream_finish(_ctx->data.output) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_set_critical(_ctx->dest_mail,
					"write(%s) failed: %s", ctx->temp_path,
					o_stream_get_error(_ctx->data.output));
			}
			ctx->failed = TRUE;
		}
	}

	if (!ctx->failed) {
		if (exmdbc_save_append(ctx) < 0)
			ctx->failed = TRUE;
	}

	o_stream_unref(&_ctx->data.output);
	i_stream_unref(&ctx->input);
	i_close_fd_path(&ctx->fd, ctx->temp_path);
	i_free(ctx->temp_path);
	index_save_context_free(_ctx);
	return ctx->failed ? -1 : 0;
}

void exmdbc_save_cancel(struct mail_save_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_save_cancel called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);

	ctx->failed = TRUE;
	(void)exmdbc_transaction_save_commit_pre(_ctx);
	(void)exmdbc_save_finish(_ctx);
}

static void exmdbc_copy_bulk_finish(struct exmdbc_save_context *ctx)
{
	fprintf(stdout, "!!! exmdbc_copy_bulk_finish called\n");
	while (ctx->src_mbox != NULL && ctx->src_mbox->pending_copy_request != NULL)
		exmdbc_mailbox_run_nofetch(ctx->src_mbox);
}

int exmdbc_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_transaction_save_commit_pre called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);
	struct mail_transaction_commit_changes *changes =
		_ctx->transaction->changes;
	uint32_t i, last_seq;

	i_assert(ctx->finished || ctx->failed);

	/* expunge all added messages from index before commit */
	last_seq = mail_index_view_get_messages_count(_ctx->transaction->view);
	if (last_seq == 0)
		return -1;
	for (i = 0; i < ctx->save_count; i++)
		mail_index_expunge(ctx->trans, last_seq - i);

	if (!ctx->failed && array_is_created(&ctx->dest_saved_uids)) {
		changes->uid_validity = ctx->dest_uid_validity;
		array_append_array(&changes->saved_uids, &ctx->dest_saved_uids);
	}
	return 0;
}

int exmdbc_transaction_save_commit(struct mailbox_transaction_context *t)
{
	fprintf(stdout, "!!! exmdbc_transaction_save_commit called\n");
	struct exmdbc_save_context *ctx = NULL;
	struct exmdbc_mailbox *src_mbox = NULL;

	if (t->save_ctx != NULL) {
		ctx = EXMDBC_SAVECTX(t->save_ctx);
		src_mbox = ctx->src_mbox;
	}

	if (src_mbox != NULL && src_mbox->pending_copy_request != NULL) {
		/* If there is still a copy command to send flush it now */
		exmdbc_copy_bulk_finish(ctx);
	}

	if (ctx != NULL)
		return ctx->failed ? -1 : 0;
	return 0;
}

void exmdbc_transaction_save_commit_post(struct mail_save_context *_ctx,
					struct mail_index_transaction_commit_result *result ATTR_UNUSED)
{
	fprintf(stdout, "!!! exmdbc_transaction_save_commit_post called\n");
	exmdbc_transaction_save_rollback(_ctx);
}

static void
exmdbc_expunge_construct_cmd_str(string_t *store_cmd,
				string_t *expunge_cmd,
				string_t *uids)
{
	fprintf(stdout, "!!! exmdbc_expunge_construct_cmd_str called\n");
	str_append(store_cmd, "UID STORE ");
	str_append_str(store_cmd, uids);
	str_append(store_cmd, " +FLAGS (\\Deleted)");
	str_append(expunge_cmd, "UID EXPUNGE ");
	str_append_str(expunge_cmd, uids);
	/* Clear already appended uids */
	str_truncate(uids, 0);
}

static void
exmdbc_expunge_send_cmd_str(struct exmdbc_save_context *ctx,
			   string_t *uids)
{
	fprintf(stdout, "!!! exmdbc_expunge_send_cmd_str called\n");
	struct exmdbc_command *store_cmd, *expunge_cmd;

	string_t *store_cmd_str, *expunge_cmd_str;
	store_cmd_str = t_str_new(128);
	expunge_cmd_str = t_str_new(128);

	exmdbc_expunge_construct_cmd_str(store_cmd_str, expunge_cmd_str, uids);
	/* Make sure line length is less than 8k */
	i_assert(str_len(store_cmd_str) < EXMDBC_SERVER_CMDLINE_MAX_LEN);
	i_assert(str_len(expunge_cmd_str) < EXMDBC_SERVER_CMDLINE_MAX_LEN);

	//TODO:EXMDBC:
	/*store_cmd = exmdbc_client_mailbox_cmd(ctx->src_mbox->client_box,
					     exmdbc_copy_rollback_store_callback,
					     ctx);
	expunge_cmd = exmdbc_client_mailbox_cmd(ctx->src_mbox->client_box,
					       exmdbc_copy_rollback_expunge_callback,
					       ctx);
	ctx->src_mbox->rollback_pending = TRUE;
	exmdbc_command_send(store_cmd, str_c(store_cmd_str));
	exmdbc_command_send(expunge_cmd, str_c(expunge_cmd_str));*/
}

static void
exmdbc_rollback_send_expunge(struct exmdbc_save_context *ctx)
{
	fprintf(stdout, "!!! exmdbc_rollback_send_expunge called\n");
	string_t *uids_str;
	struct seqset_builder *seqset_builder;
	struct seq_range_iter iter;
	unsigned int i = 0;
	uint32_t uid;

	if (!array_not_empty(&ctx->src_mbox->copy_rollback_expunge_uids))
		return;

	uids_str = t_str_new(128);
	seqset_builder = seqset_builder_init(uids_str);
	seq_range_array_iter_init(&iter, &ctx->src_mbox->copy_rollback_expunge_uids);

	/* Iterate over all uids that must be rolled back */
	while (seq_range_array_iter_nth(&iter, i++, &uid)) {
		/* Try to add the to the seqset builder while respecting
		   the maximum length of EXMDBC_SERVER_CMDLINE_MAX_LEN. */
		if (!seqset_builder_try_add(seqset_builder,
					    EXMDBC_SERVER_CMDLINE_MAX_LEN -
					    strlen("UID STORE  +FLAGS (\\Deleted)"),
					    uid)) {
			/* Maximum length is reached send the rollback
			   and wait for it to be finished. */
			exmdbc_expunge_send_cmd_str(ctx, uids_str);
			while (ctx->src_mbox->rollback_pending)
				exmdbc_mailbox_run_nofetch(ctx->src_mbox);

			/* Truncate the uids_str and create a new
			   seqset_builder for the next command */
			seqset_builder_deinit(&seqset_builder);
			str_truncate(uids_str, 0);
			seqset_builder = seqset_builder_init(uids_str);
			/* Make sure the current uid which is part of
			   the next uid_str */
			seqset_builder_add(seqset_builder, uid);
		}
	}
	if (str_len(uids_str) > 0)
		exmdbc_expunge_send_cmd_str(ctx, uids_str);
	while (ctx->src_mbox->rollback_pending)
		exmdbc_mailbox_run_nofetch(ctx->src_mbox);
}

static void exmdbc_copy_bulk_ctx_deinit(struct exmdbc_save_context *ctx)
{
	fprintf(stdout, "!!! exmdbc_copy_bulk_ctx_deinit called\n");
	/* Clean up the pending copy and the context attached to it */
	str_truncate(ctx->src_mbox->pending_copy_cmd, 0);
	i_free(ctx->src_mbox->copy_dest_box);
}

void exmdbc_transaction_save_rollback(struct mail_save_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_transaction_save_rollback called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);

       if ((ctx->src_mbox != NULL && ctx->src_mbox->pending_copy_request != NULL) ||
	   !ctx->finished) {
	       /* There is still a pending copy which should not be send
		  as rollback() is called or the transaction has not yet
		  finished and rollback is called */
	       ctx->failed = TRUE;
	       (void)exmdbc_transaction_save_commit_pre(_ctx);

	       i_assert(ctx->finished || ctx->src_mbox != NULL);
	       /* Clean up the pending copy and the context attached to it */
	       if (ctx->src_mbox != NULL) {
		       if (ctx->src_mbox->pending_copy_request != NULL) {
			       seqset_builder_deinit(&ctx->src_mbox->pending_copy_request->uidset_builder);
			       i_free(ctx->src_mbox->pending_copy_request);
		       }
		       exmdbc_copy_bulk_ctx_deinit(ctx);

	//TODO:EXMDBC:
	//exmdbc_client_stop(ctx->src_mbox->storage->client->client);
	       }
       }

	/* Expunge all added messages from index */
	if (ctx->failed && array_is_created(&ctx->dest_saved_uids)) {
		i_assert(ctx->src_mbox != NULL);
		seq_range_array_merge(&ctx->src_mbox->copy_rollback_expunge_uids, &ctx->dest_saved_uids);
		/* Make sure context is not finished already */
		ctx->finished = FALSE;
		exmdbc_rollback_send_expunge(ctx);
		array_free(&ctx->dest_saved_uids);
	}

	if (ctx->finished || ctx->failed) {
		array_free(&ctx->dest_saved_uids);
		i_free(ctx);
	}
}

static bool exmdbc_is_mail_expunged(struct exmdbc_mailbox *mbox, uint32_t uid)
{
	fprintf(stdout, "!!! exmdbc_is_mail_expunged called\n");
	if (array_is_created(&mbox->delayed_expunged_uids) &&
	    seq_range_exists(&mbox->delayed_expunged_uids, uid))
		return TRUE;
	if (mbox->delayed_sync_trans == NULL)
		return FALSE;

	struct mail_index_view *view =
		mail_index_transaction_get_view(mbox->delayed_sync_trans);
	uint32_t seq;
	return mail_index_lookup_seq(view, uid, &seq) &&
		mail_index_transaction_is_expunged(mbox->delayed_sync_trans, seq);
}

int exmdbc_copy(struct mail_save_context *_ctx, struct mail *mail)
{
	fprintf(stdout, "!!! exmdbc_copy called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);
	struct mailbox_transaction_context *_t = _ctx->transaction;
	struct exmdbc_msgmap *src_msgmap;
	uint32_t rseq;
	int ret;

	i_assert((_t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (_t->box->storage == mail->box->storage) {
		/* Currently we don't support copying mails from multiple
		   different source mailboxes within the same transaction. */
		i_assert(ctx->src_mbox == NULL || &ctx->src_mbox->box == mail->box);
		ctx->src_mbox = EXMDBC_MAILBOX(mail->box);
		if (!mail->expunged && exmdbc_is_mail_expunged(ctx->mbox, mail->uid))
			mail_set_expunged(mail);
		/* same server, we can use COPY for the mail */

		//TODO:EXMDBC:
		// src_msgmap =
		// 	exmdbc_client_mailbox_get_msgmap(ctx->src_mbox->client_box);
		// if (mail->expunged ||
		//     !exmdbc_msgmap_uid_to_rseq(src_msgmap, mail->uid, &rseq)) {
		// 	mail_storage_set_error(mail->box->storage,
		// 			       MAIL_ERROR_EXPUNGED,
		// 			       "Some of the requested messages no longer exist.");
		// 	ctx->finished = TRUE;
		// 	index_save_context_free(_ctx);
		// 	return -1;
		// }
		// /* Mail has not been expunged and can be copied. */
		// if (ctx->mbox->capabilities == 0) {
		// 	/* The destination mailbox has not yet been selected
		// 	   so the capabilities are unknown */
		// 	if (exmdbc_client_get_capabilities(ctx->mbox->storage->client->client,
		// 				      &ctx->mbox->capabilities) < 0) {
		// 		mail_storage_set_error(mail->box->storage,
		// 				       MAIL_ERROR_UNAVAILABLE,
		// 				       "Failed to determine capabilities for mailbox.");
		// 		ctx->finished = TRUE;
		// 		index_save_context_free(_ctx);
		// 		return -1;
		// 	}
		// }
		// if ((ctx->mbox->capabilities & EXMDBC_CAPABILITY_UIDPLUS) != 0)
		// 	ret = exmdbc_copy_bulk(ctx, mail);
		// else
		// 	ret = exmdbc_copy_simple(_ctx, mail);
		// index_save_context_free(_ctx);
		return ret;
	}
	return mail_storage_copy(_ctx, mail);
}
