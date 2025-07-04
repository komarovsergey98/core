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
	struct mail_index_transaction *trans;

	int fd;
	char *temp_path;
	struct istream *input;

	uint32_t dest_uid_validity;
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

	i_assert(_ctx->data.output == NULL);

	if (!ctx->finished)
		exmdbc_save_cancel(&ctx->ctx);

	//TODO:EXMDBC Save rollback

	pool_unref(&ctx->pool);
}

struct mail_save_context *
exmdbc_save_alloc(struct mailbox_transaction_context *t)
{
	fprintf(stdout, "!!! exmdbc_save_alloc called\n");
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

int create_temp_file(const char **path_r)
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
	fprintf(stdout, "!!! exmdbc_save_begin called\n");
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
	struct exmdbc_mailbox *mbox = ctx->mbox;
	struct exmdb_client *client = mbox->storage->client->client;

	if (_ctx->data.output) {
		o_stream_uncork(_ctx->data.output);
		o_stream_flush(_ctx->data.output);
		o_stream_unref(&_ctx->data.output);
	}

	FILE *f = fopen(ctx->temp_path, "rb");
	if (!f) {
		fprintf(stderr, "[EXMDBC] Can't open temp file %s\n", ctx->temp_path);
		ctx->failed = TRUE;
		return -1;
	}
	fseek(f, 0, SEEK_END);
	size_t file_len = ftell(f);
	rewind(f);

	char *body = malloc(file_len);
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

	int ret = exmdbc_client_save_body(
		client,
		mbox->folder_id,
		mbox->box.list->ns->user->username,
		body,
		file_len
	);
	free(body);
	unlink(ctx->temp_path);
	i_free(ctx->temp_path);
	return ret;
}

void exmdbc_save_cancel(struct mail_save_context *_ctx)
{
	fprintf(stdout, "!!! exmdbc_save_cancel called\n");
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);

	ctx->failed = TRUE;
	(void)exmdbc_transaction_save_commit_pre(_ctx);
	(void)exmdbc_save_finish(_ctx);
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


	//TODO:EXMDBC: Save commit pre
	// ret = exmdbc_rpc_save_message(ctx);
	// if (ret < 0) {
	// 	exmdbc_rpc_rollback_message(ctx);
	// 	return -1;
	// }
	// if (mail_index_transaction_commit(&_t->itrans) < 0) {
	// //Do it if we gromox has rollback oportunity
	// 	exmdbc_rpc_rollback_message(ctx);
	// 	return -1;
	// }
	return 0;
}

void exmdbc_transaction_save_commit_post(struct mail_save_context *_ctx,
struct mail_index_transaction_commit_result *result) {
	struct exmdbc_save_context *ctx = EXMDBC_SAVECTX(_ctx);

	_ctx->transaction = NULL;
	pool_unref(&ctx->pool);
}

int exmdbc_copy(struct mail_save_context *_ctx, struct mail *mail)
{
	fprintf(stdout, "!!! exmdbc_copy called\n");
	struct mailbox_transaction_context *_t = _ctx->transaction;
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_t->box);
	uint32_t rseq;
	int ret;

	i_assert((_t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	//TODO: EXMDBC: Copy mail from mail->box(src) to current mbox
	// ezr to do this in c++
	// ret = exmdbc_rpc_copy_message(mail, dst_mbox);
	// if (ret < 0) {
	// 	// here i need to do rollback
	// 	return -1;
	// }
	//
	// // mail_index_append()
	//
	// if (mail_index_transaction_commit(&_t->itrans) < 0) {
	// 	// if failed i need to remove new message from gromox
	// 	exmdbc_rpc_delete_message(dst_mbox, /* new_uid_or_id */);
	// 	return -1;
	// }

	return mail_storage_copy(_ctx, mail);
}
