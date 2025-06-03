/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-search.h"
#include "exmdbc-storage.h"
#include "exmdbc-search.h"

#include <stdio.h>

#include "exmdbc-mailbox.h"

#define EXMDBC_SEARCHCTX(obj) \
	MODULE_CONTEXT(obj, exmdbc_storage_module)

struct exmdbc_search_context {
	union mail_search_module_context module_ctx;

	ARRAY_TYPE(seq_range) rseqs;
	struct seq_range_iter iter;
	unsigned int n;
	bool finished;
	bool success;
};

static MODULE_CONTEXT_DEFINE_INIT(exmdbc_storage_module,
				  &mail_storage_module_register);

static bool exmdbc_build_search_query(struct exmdbc_mailbox *mbox,
				     const struct mail_search_args *args,
				     const char **query_r)
{
	fprintf(stdout, "!!! exmdbc_build_search_query called\n");
	string_t *str = t_str_new(128);

	//TODO:EXMDBC:
	*query_r = str_c(str);
	return TRUE;
}

struct mail_search_context *
exmdbc_search_init(struct mailbox_transaction_context *t,
		  struct mail_search_args *args,
		  const enum mail_sort_type *sort_program,
		  enum mail_fetch_field wanted_fields,
		  struct mailbox_header_lookup_ctx *wanted_headers)
{
	fprintf(stdout, "!!! exmdbc_search_init called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(t->box);
	struct mail_search_context *ctx;
	struct exmdbc_search_context *ictx;
	struct exmdbc_command *cmd;
	const char *search_query;

	ctx = index_storage_search_init(t, args, sort_program,
					wanted_fields, wanted_headers);

	if (!exmdbc_build_search_query(mbox, args, &search_query)) {
		/* can't optimize this with SEARCH */
		return ctx;
	}

	ictx = i_new(struct exmdbc_search_context, 1);
	i_array_init(&ictx->rseqs, 64);
	MODULE_CONTEXT_SET(ctx, exmdbc_storage_module, ictx);


	//TODO:EXMDBC:
	return ctx;
}

static void exmdbc_search_set_matches(struct mail_search_arg *args)
{
	fprintf(stdout, "!!! exmdbc_search_set_matches called\n");
	for (; args != NULL; args = args->next) {
		if (args->type == SEARCH_OR ||
		    args->type == SEARCH_SUB)
			exmdbc_search_set_matches(args->value.subargs);
		args->match_always = TRUE;
		args->result = 1;
	}
}

bool exmdbc_search_next_update_seq(struct mail_search_context *ctx)
{
	fprintf(stdout, "!!! exmdbc_search_next_update_seq called\n");
	struct exmdbc_search_context *ictx = EXMDBC_SEARCHCTX(ctx);

	if (ictx == NULL || !ictx->success)
		return index_storage_search_next_update_seq(ctx);

	if (!seq_range_array_iter_nth(&ictx->iter, ictx->n++, &ctx->seq))
		return FALSE;
	ctx->progress_cur = ctx->seq;

	exmdbc_search_set_matches(ctx->args->args);
	return TRUE;
}

int exmdbc_search_deinit(struct mail_search_context *ctx)
{
	fprintf(stdout, "!!! exmdbc_search_deinit called\n");
	struct exmdbc_search_context *ictx = EXMDBC_SEARCHCTX(ctx);

	if (ictx != NULL) {
		array_free(&ictx->rseqs);
		i_free(ictx);
	}
	return index_storage_search_deinit(ctx);
}

void exmdbc_search_reply_search(const struct exmdbc_arg *args,
			       struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_search_reply_search called\n");
	struct event *event = mbox->box.event;

	//TODO:EXMDBC:
	// struct exmdbc_msgmap *msgmap =
	// exmdbc_client_mailbox_get_msgmap(mbox->client_box);
	// const char *atom;
	// uint32_t uid, rseq;
	//
	// if (mbox->search_ctx == NULL) {
	// 	e_error(event, "Unexpected SEARCH reply");
	// 	return;
	// }
	//
	// /* we're doing UID SEARCH, so need to convert UIDs to sequences */
	// for (unsigned int i = 0; args[i].type != IMAP_ARG_EOL; i++) {
	// 	if (!exmdbc_arg_get_atom(&args[i], &atom) ||
	// 	    str_to_uint32(atom, &uid) < 0 || uid == 0) {
	// 		e_error(event, "Invalid SEARCH reply");
	// 		break;
	// 	}
	// 	if (exmdbc_msgmap_uid_to_rseq(msgmap, uid, &rseq))
	// 		seq_range_array_add(&mbox->search_ctx->rseqs, rseq);
	// }
}

void exmdbc_search_reply_esearch(const struct exmdbc_arg *args,
				struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_search_reply_esearch called\n");
	struct event *event = mbox->box.event;
	const char *atom;

	if (mbox->search_ctx == NULL) {
		e_error(event, "Unexpected ESEARCH reply");
		return;
	}

	//TODO:EXMDBC:
	// /* It should contain ALL <seqset> or nonexistent if nothing matched */
	// if (args[0].type != IMAP_ARG_EOL &&
	//     (!exmdbc_arg_atom_equals(&args[0], "ALL") ||
	//      !exmdbc_arg_get_atom(&args[1], &atom) ||
	//      imap_seq_set_nostar_parse(atom, &mbox->search_ctx->rseqs) < 0))
	// 	e_error(event, "Invalid ESEARCH reply");
}
