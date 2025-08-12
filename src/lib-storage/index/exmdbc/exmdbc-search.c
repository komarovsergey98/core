/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-search.h"
#include "exmdbc-storage.h"
#include "exmdbc-search.h"

#include <exmdb_client_c.h>
#include <stdio.h>

#include "exmdbc-mailbox.h"

#define EXMDBC_SEARCHCTX(obj) \
	MODULE_CONTEXT(obj, exmdbc_storage_module)

struct exmdbc_search_context {
	union mail_search_module_context module_ctx;
	uint32_t *uids;
	unsigned count;
	unsigned pos;
	bool finished;
};

static MODULE_CONTEXT_DEFINE_INIT(exmdbc_storage_module,
				  &mail_storage_module_register);

static bool exmdbc_extract_single_uid_range(struct exmdbc_mailbox *mbox,
		const struct mail_search_arg *arg,
		uint32_t *lo_r, uint32_t *hi_r)
{
	ARRAY_TYPE(seq_range) uids;
	t_array_init(&uids, 8);

	if (arg->type == SEARCH_SEQSET) {
		/* convert message sequences -> UIDs */
		mailbox_get_uid_range(&mbox->box, &arg->value.seqset, &uids);
	} else if (arg->type == SEARCH_UIDSET) {
		/* copy the UID ranges as elements into our local array */
		const struct seq_range *in_ranges;
		unsigned int in_count = 0;
		in_ranges = array_get(&arg->value.seqset, &in_count);
		if (in_count == 0)
			return FALSE;
		array_append(&uids, in_ranges, in_count);
	} else {
		return FALSE;
	}

	if (array_count(&uids) != 1)
		return FALSE; /* MVP: support only one contiguous range for server offload */

	const struct seq_range *r = array_front(&uids);
	uint32_t lo = r->seq1 ? r->seq1 : 1;
	uint32_t hi = r->seq2 ? r->seq2 : lo;

	*lo_r = lo;
	*hi_r = hi;
	return TRUE;
}

static bool exmdbc_build_spec_from_args(struct exmdbc_mailbox *mbox,
                                        const struct mail_search_arg *args,
                                        struct exmdbc_search_spec *spec)
{
    i_zero(spec);
    bool have_uid = FALSE;

    for (const struct mail_search_arg *a = args; a != NULL; a = a->next) {
        if (a->match_not)
            return FALSE; /* TODO:EXMDBC: could support later */

        switch (a->type) {
        case SEARCH_ALL:
            break;

        case SEARCH_OR:
        case SEARCH_SUB:
            return FALSE; /* TODO: OR/() */

        case SEARCH_SEQSET:
		case SEARCH_UIDSET: {
        		uint32_t lo, hi;
        		if (!exmdbc_extract_single_uid_range(mbox, a, &lo, &hi))
        			return FALSE;
        		if (have_uid) /* already had a range -> not supported in MVP */
        			return FALSE;
        		spec->uid_lo = lo;
        		spec->uid_hi = hi;
        		have_uid = TRUE;
        		break;
		}

	    case SEARCH_FLAGS: {
	        /* In this Dovecot build value.flags is a single enum mail_flags.
			   We only optimize \Seen; anything else → fallback. */
	        enum mail_flags f = a->value.flags;

	        if (f == MAIL_SEEN) {
        		if (a->match_not)
        			spec->want_unseen = 1; /* UNSEEN */
        		else
        			spec->want_seen = 1;   /* SEEN */
	        } else {
        		/* Other system flags (\Answered, \Deleted, …) → fallback for now */
        		return FALSE;
	        }
	        break;
        }

        case SEARCH_SINCE:
            if (a->value.time != 0 && (spec->since_utc == 0 || a->value.time < (time_t)spec->since_utc))
                spec->since_utc = (uint64_t)a->value.time;
            break;
        case SEARCH_BEFORE:
            if (a->value.time != 0 && (spec->before_utc == 0 || a->value.time < (time_t)spec->before_utc))
                spec->before_utc = (uint64_t)a->value.time;
            break;
        case SEARCH_ON:
            if (a->value.time != 0) {
                spec->since_utc  = (uint64_t)a->value.time;
                spec->before_utc = (uint64_t)a->value.time + 24*60*60;
            }
            break;

        case SEARCH_SMALLER:
            spec->smaller_than = a->value.size;
            break;
        case SEARCH_LARGER:
            spec->larger_than = a->value.size;
            break;

        case SEARCH_HEADER:
        case SEARCH_HEADER_ADDRESS:
        case SEARCH_HEADER_COMPRESS_LWSP: {
            const char *h = a->hdr_field_name, *v = a->value.str;
            if (v == NULL || *v == '\0') break;
            if (strcasecmp(h, "Subject") == 0) spec->subject = v;
            else if (strcasecmp(h, "From") == 0) spec->from_ = v;
            else if (strcasecmp(h, "To") == 0)   spec->to_   = v;
            else if (strcasecmp(h, "Cc") == 0)   spec->cc    = v;
            else return FALSE;
            break;
        }

        case SEARCH_BODY:
        case SEARCH_TEXT:
        case SEARCH_MODSEQ:
        case SEARCH_KEYWORDS:
        case SEARCH_MAILBOX:
        case SEARCH_MAILBOX_GUID:
        case SEARCH_MAILBOX_GLOB:
        case SEARCH_REAL_UID:
        case SEARCH_INTHREAD:
        case SEARCH_GUID:
        case SEARCH_MIMEPART:
        case SEARCH_SAVEDATESUPPORTED:
            return FALSE; /* not in MVP */
        default:
            return FALSE;
        }
    }
    return TRUE;
}

struct mail_search_context *
exmdbc_search_init(struct mailbox_transaction_context *t,
		  struct mail_search_args *args,
		  const enum mail_sort_type *sort_program,
		  enum mail_fetch_field wanted_fields,
		  struct mailbox_header_lookup_ctx *wanted_headers)
{
	i_debug("[exmdbc] exmdbc_search_init called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(t->box);
	struct mail_search_context *_ctx =
		index_storage_search_init(t, args, sort_program, wanted_fields, wanted_headers);

	struct exmdbc_search_spec spec;
	if (!exmdbc_build_spec_from_args(mbox, args->args, &spec)) {
		i_debug("exmdbc: SEARCH fallback to local (unsupported query)");
		return _ctx;
	}

	uint32_t *uids = NULL; unsigned count = 0;
	const char *username = t->box->list->ns->user->username;

	int rc = exmdbc_client_search_uids(mbox->storage->client->client,
									mbox->folder_id, username,
									&spec, &uids, &count);
	if (rc < 0) {
		i_debug("exmdbc: SEARCH RPC failed, fallback to local");
		return _ctx;
	}

	struct exmdbc_search_context *ctx = i_new(struct exmdbc_search_context, 1);
	ctx->uids = uids;
	ctx->count = count;
	ctx->pos = 0;
	ctx->finished = TRUE;

	MODULE_CONTEXT_SET(_ctx, exmdbc_storage_module, ctx);
	i_debug("exmdbc: SEARCH offloaded: %u hits", count);
	return _ctx;

}

static void exmdbc_search_set_matches(struct mail_search_arg *args)
{
	i_debug("[exmdbc] exmdbc_search_set_matches called\n");
	for (; args != NULL; args = args->next) {
		if (args->type == SEARCH_OR ||
		    args->type == SEARCH_SUB)
			exmdbc_search_set_matches(args->value.subargs);
		args->match_always = TRUE;
		args->result = 1;
	}
}

bool exmdbc_search_next_nonblock(struct mail_search_context *_ctx,
								 struct mail **mail_r, bool *tryagain_r)
{
	i_debug("[exmdbc] exmdbc_search_next_nonblock called\n");
	struct exmdbc_search_context *ctx =
		MODULE_CONTEXT(_ctx, exmdbc_storage_module);

	if (tryagain_r != NULL)
		*tryagain_r = FALSE;

	if (ctx == NULL) {
		return index_storage_search_next_nonblock(_ctx, mail_r, tryagain_r);
	}

	struct mailbox *box = _ctx->transaction->box;

	while (ctx->pos < ctx->count) {
		uint32_t uid = ctx->uids[ctx->pos++];
		uint32_t seq = 0;

		if (!mail_index_lookup_seq(box->view, uid, &seq) || seq == 0)
			continue;

		struct mail *mail = mail_alloc(_ctx->transaction, 0, NULL);
		mail_set_seq(mail, seq);
		*mail_r = mail;
		return TRUE;
	}

	*mail_r = NULL;
	return FALSE;
}

bool exmdbc_search_next_update_seq(struct mail_search_context *_ctx)
{
	i_debug("[exmdbc] exmdbc_search_next_update_seq called\n");
	struct exmdbc_search_context *ctx =
		MODULE_CONTEXT(_ctx, exmdbc_storage_module);

	return index_storage_search_next_update_seq(_ctx);
}

int exmdbc_search_deinit(struct mail_search_context *ctx)
{
	i_debug("[exmdbc] exmdbc_search_deinit called\n");
	struct exmdbc_search_context *xctx = MODULE_CONTEXT(ctx, exmdbc_storage_module);
	if (xctx != NULL) {
		free(xctx->uids);
		i_free(xctx);
	}
	index_storage_search_deinit(ctx);
}

void exmdbc_search_reply_search(const struct exmdbc_arg *args,
			       struct exmdbc_mailbox *mbox)
{
	i_debug("[exmdbc] exmdbc_search_reply_search called\n");
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
	i_debug("[exmdbc] exmdbc_search_reply_esearch called\n");
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
