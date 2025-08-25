/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include <exmdbc-mailbox.h>
#include <exmdb_client_c.h>
#include <stdio.h>
#include <maildir/maildir-uidlist.h>

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "mail-copy.h"
#include "mailbox-list-private.h"
#include "exmdbc-msgmap.h"
#include "exmdbc-storage.h"

struct exmdbc_save_context {
	struct mail_save_context ctx;
	pool_t pool;

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

void exmdbc_transaction_save_rollback(struct mail_save_context *_ctx)
{
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);

	if (ctx->finished || ctx->failed) {
		i_assert(ctx->src_mbox != NULL);
		ctx->finished = FALSE;
		array_free(&ctx->dest_saved_uids);
		i_free(ctx);
	}
}

struct mail_save_context *
exmdbc_save_alloc(struct mailbox_transaction_context *t)
{
	i_debug("[exmdbc] exmdbc_save_alloc called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(t->box);
	struct exmdbc_save_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("exmdbc_save_context", 4096);
	ctx = p_new(pool, struct exmdbc_save_context, 1);

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL) {
		ctx = i_new(struct exmdbc_save_context, 1);
		ctx->ctx.transaction = t;
		ctx->pool = pool;
		ctx->mbox = mbox;
		ctx->trans = t->itrans;
		ctx->fd = -1;
		t->save_ctx = &ctx->ctx;
	}
	return t->save_ctx;
}

static int create_temp_file(char **path_r)
{
	static char template[] = "/tmp/exmdbc_msg_XXXXXX";
	char *path = strdup(template); // Копія, яку можна модифікувати
	if (!path) {
		*path_r = NULL;
		return -1;
	}
	int fd = mkstemp(path);
	if (fd == -1) {
		free(path);
		*path_r = NULL;
		return -1;
	}
	*path_r = path;
	return fd;
}

int exmdbc_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	i_debug("[exmdbc] exmdbc_save_begin called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);
	int temp_fd = create_temp_file(&ctx->temp_path);
	if (temp_fd == -1) {
		mail_set_critical(_ctx->dest_mail, "Couldn't create temp file %s", ctx->temp_path);
		ctx->failed = TRUE;
		return -1;
	}
	ctx->fd = temp_fd;
	ctx->temp_path = i_strdup(ctx->temp_path);
	ctx->input = input;
	_ctx->data.output = o_stream_create_fd_file(ctx->fd, 0, FALSE);
	o_stream_cork(_ctx->data.output);
	ctx->finished = FALSE;
	return 0;
}

int exmdbc_save_continue(struct mail_save_context *_ctx)
{

	i_debug("[exmdbc] exmdbc_save_continue called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);

	if (ctx->failed)
		return -1;

	if (index_storage_save_continue(_ctx, ctx->input, NULL) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}
int exmdbc_save_append(struct exmdbc_save_context *ctx)
{
	struct mail_save_context *_ctx = &ctx->ctx;
	struct exmdbc_mailbox *mbox = ctx->mbox;
	struct exmdb_client *client = mbox->storage->client->client;

	FILE *f = fopen(ctx->temp_path, "rb");
	if (!f) {
		fprintf(stderr, "[EXMDBC] Can't open temp file %s\n", ctx->temp_path);
		ctx->failed = TRUE;
		return -1;
	}
	fseek(f, 0, SEEK_END);
	size_t file_len = ftell(f);
	rewind(f);

	char *body = malloc(file_len ? file_len : 1);
	if (!body) {
		fclose(f);
		fprintf(stderr, "[EXMDBC] Malloc failed\n");
		ctx->failed = TRUE;
		return -1;
	}
	if (fread(body, 1, file_len, f) != file_len) {
		fclose(f);
		free(body);
		fprintf(stderr, "[EXMDBC] Read failed\n");
		ctx->failed = TRUE;
		return -1;
	}
	fclose(f);

	uint64_t outmid = 0;
	int ret = exmdbc_client_save_body(
		client,
		mbox->folder_id,
		mbox->box.list->ns->user->username,
		body,
		file_len,
		&outmid,
		MAIL_RECENT
	);

	if (ret == 0 && outmid > 0) {
		uint32_t lseq = 0;
		mail_index_append(ctx->trans, outmid, &lseq);
		mail_index_update_flags(ctx->trans, lseq, MODIFY_REPLACE, _ctx->data.flags);

		// keywords, internaldatу???

		if (ctx->dest_uid_validity == 0)
			ctx->dest_uid_validity = outmid;


		if (!array_is_created(&ctx->dest_saved_uids))
			i_array_init(&ctx->dest_saved_uids, 8);

		seq_range_array_add_with_init(&ctx->dest_saved_uids,
						  32, outmid);
		mail_set_seq_saving(_ctx->dest_mail, lseq);

	}

	free(body);
	return ret;
}

int exmdbc_save_finish(struct mail_save_context *_ctx)
{
	i_debug("[exmdbc] exmdbc_save_finish called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);
	ctx->finished = TRUE;

	if (_ctx->data.output) {
		o_stream_uncork(_ctx->data.output);
		o_stream_flush(_ctx->data.output);
		o_stream_unref(&_ctx->data.output);
	}

	exmdbc_save_append(ctx);

	if (ctx->temp_path) {
		unlink(ctx->temp_path);
		i_close_fd_path(&ctx->fd, ctx->temp_path);
		i_free(ctx->temp_path);
	}
	index_save_context_free(_ctx);
	return ctx->failed ? -1 : 0;
}

void exmdbc_save_cancel(struct mail_save_context *_ctx)
{
	i_debug("[exmdbc] exmdbc_save_cancel called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);

	ctx->failed = TRUE;
	(void)exmdbc_transaction_save_commit_pre(_ctx);
	(void)exmdbc_save_finish(_ctx);
}

int exmdbc_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	i_debug("[exmdbc] exmdbc_transaction_save_commit_pre called\n");

	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);
	struct mail_transaction_commit_changes *changes =
		_ctx->transaction->changes;
	uint32_t i, last_seq, uid_validity;

	i_assert(ctx->finished || ctx->failed);

	/* expunge all added messages from index before commit */
	last_seq = mail_index_view_get_messages_count(_ctx->transaction->view);
	if (last_seq == 0)
		return -1;
	for (i = 0; i < ctx->save_count; i++)
		mail_index_expunge(ctx->trans, last_seq - i);

	uid_validity = ctx->dest_uid_validity;
	if (!ctx->failed && array_is_created(&ctx->dest_saved_uids)) {
		changes->uid_validity = uid_validity;
		array_append_array(&changes->saved_uids, &ctx->dest_saved_uids);

		if (ctx->mbox->sync_uid_validity != uid_validity) {
			ctx->mbox->sync_uid_validity = uid_validity;
			exmdbc_mail_cache_free(&ctx->mbox->prev_mail_cache);
			exmdbc_sync_uid_validity(ctx->mbox);
		}
	}
	return 0;
}

void exmdbc_transaction_save_commit_post(struct mail_save_context *_ctx,
struct mail_index_transaction_commit_result *result) {

	exmdbc_transaction_save_rollback(_ctx);
}

static bool exmdbc_is_mail_expunged(struct exmdbc_save_context *ctx, uint32_t uid)
{
	if (ctx->trans == NULL)
		return FALSE;

	struct mail_index_view *view =
		mail_index_transaction_get_view(ctx->trans);
	uint32_t seq;
	return mail_index_lookup_seq(view, uid, &seq);
}

int exmdbc_copy(struct mail_save_context *_ctx, struct mail *mail)
{
	i_debug("[exmdbc] exmdbc_copy called\n");

	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);
	struct mailbox_transaction_context *_t = _ctx->transaction;

	i_assert((_t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	ctx->src_mbox = EXMDBC_MAILBOX(mail->box);
	if (!mail->expunged && exmdbc_is_mail_expunged(ctx, mail->uid))
		mail_set_expunged(mail);

	if (_t->box->storage == mail->box->storage) {
		struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(mail->box);
		struct exmdbc_mailbox *dst_mbox = EXMDBC_MAILBOX(_t->box);
		uint64_t mid = mail->uid;
		uint64_t dst_fid = dst_mbox->folder_id;
		const char *username = _t->box->list->ns->user->username;

		int ret = exmdbc_client_copy_message(
			mbox->storage->client->client,
			mid,                  // src_message_id
			dst_fid,              // dst_folder_id
			username
		);
		index_save_context_free(_ctx);
		if (ret == 0)
			return 0;

		mail_storage_set_error(mail->box->storage, MAIL_ERROR_TEMP,
			"Failed to copy message via Gromox RPC");
		return -1;
	}
	return mail_storage_copy(_ctx, mail);
}
