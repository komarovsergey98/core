/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "sort.h"
#include "mail-cache.h"
#include "mail-index-modseq.h"
#include "index-sync-private.h"
#include "exmdbc-msgmap.h"
#include "exmdbc-mailbox.h"
#include "exmdbc-storage.h"
#include "exmdbc-sync.h"

#include <stdio.h>

struct exmdbc_sync_command {
	struct exmdbc_sync_context *ctx;
	char *cmd_str;
	bool ignore_no;
};

static void exmdbc_sync_callback(const struct imapc_command_reply *reply, void *context) {
	fprintf(stdout, "!!! exmdbc_sync_callback called\n");
	struct exmdbc_sync_command *cmd = context;
	struct exmdbc_sync_context *ctx = cmd->ctx;
}

static struct exmdbc_command * exmdbc_sync_cmd_full(struct exmdbc_sync_context *ctx, const char *cmd_str, bool ignore_no) {
	fprintf(stdout, "!!! exmdbc_sync_cmd_full called\n");
	struct exmdbc_sync_command *sync_cmd;
	struct exmdbc_command *cmd;

	sync_cmd = i_new(struct exmdbc_sync_command, 1);
	sync_cmd->ctx = ctx;
	sync_cmd->cmd_str = i_strdup(cmd_str);
	sync_cmd->ignore_no = ignore_no;

	ctx->sync_command_count++;
	//TODO:EXMDBC:
	return cmd;
}

static struct imapc_command * exmdbc_sync_cmd(struct exmdbc_sync_context *ctx, const char *cmd_str) {
	fprintf(stdout, "!!! exmdbc_sync_cmd called\n");
	return exmdbc_sync_cmd_full(ctx, cmd_str, FALSE);
}

static unsigned int exmdbc_sync_store_hash(const struct exmdbc_sync_store *store) {
	fprintf(stdout, "!!! exmdbc_sync_store_hash called\n");
	return str_hash(store->flags) ^ store->modify_type;
}

static int exmdbc_sync_store_cmp(const struct exmdbc_sync_store *store1, const struct exmdbc_sync_store *store2) {
	fprintf(stdout, "!!! exmdbc_sync_store_cmp called\n");
	if (store1->modify_type != store2->modify_type)
		return 1;
	return strcmp(store1->flags, store2->flags);
}

static const char *exmdbc_sync_flags_sort(const char *flags) {
	fprintf(stdout, "!!! exmdbc_sync_flags_sort called\n");
	if (strchr(flags, ' ') == NULL)
		return flags;

	const char **str = t_strsplit(flags, " ");
	i_qsort(str, str_array_length(str), sizeof(const char *),
		i_strcasecmp_p);
	return t_strarray_join(str, " ");
}

static void exmdbc_sync_store_flush(struct exmdbc_sync_context *ctx) {
	fprintf(stdout, "!!! exmdbc_sync_store_flush called\n");
	struct exmdbc_sync_store *store;
	const char *sorted_flags;

	if (ctx->prev_uid1 == 0)
		return;

	sorted_flags = exmdbc_sync_flags_sort(str_c(ctx->prev_flags));
	struct exmdbc_sync_store store_lookup = {
		.modify_type = ctx->prev_modify_type,
		.flags = sorted_flags,
	};
	store = hash_table_lookup(ctx->stores, &store_lookup);
	if (store == NULL) {
		store = p_new(ctx->pool, struct exmdbc_sync_store, 1);
		store->modify_type = ctx->prev_modify_type;
		store->flags = p_strdup(ctx->pool, sorted_flags);
		p_array_init(&store->uids, ctx->pool, 4);
		hash_table_insert(ctx->stores, store, store);
	}
	seq_range_array_add_range(&store->uids, ctx->prev_uid1, ctx->prev_uid2);
}

static void exmdbc_sync_store(struct exmdbc_sync_context *ctx, enum modify_type modify_type, uint32_t uid1, uint32_t uid2,
		 const char *flags) {
	fprintf(stdout, "!!! exmdbc_sync_store called\n");
	if (ctx->prev_flags == NULL) {
		ctx->prev_flags = str_new(ctx->pool, 128);
		hash_table_create(&ctx->stores, ctx->pool, 0,
				  exmdbc_sync_store_hash, exmdbc_sync_store_cmp);
	}

	if (ctx->prev_uid1 != uid1 || ctx->prev_uid2 != uid2 ||
	    ctx->prev_modify_type != modify_type) {
		exmdbc_sync_store_flush(ctx);
		ctx->prev_uid1 = uid1;
		ctx->prev_uid2 = uid2;
		ctx->prev_modify_type = modify_type;
		str_truncate(ctx->prev_flags, 0);
	}
	if (str_len(ctx->prev_flags) > 0)
		str_append_c(ctx->prev_flags, ' ');
	str_append(ctx->prev_flags, flags);
}

static void exmdbc_sync_finish_store(struct exmdbc_sync_context *ctx) {
	fprintf(stdout, "!!! exmdbc_sync_finish_store called\n");
	struct hash_iterate_context *iter;
	struct exmdbc_sync_store *store;
	string_t *cmd = t_str_new(128);

	exmdbc_sync_store_flush(ctx);

	if (!hash_table_is_created(ctx->stores))
		return;

	iter = hash_table_iterate_init(ctx->stores);
	while (hash_table_iterate(iter, ctx->stores, &store, &store)) {
		str_truncate(cmd, 0);
		str_append(cmd, "UID STORE ");
		//TODO:EXMDBC:
		//imap_write_seq_range(cmd, &store->uids);
		str_printfa(cmd, " %cFLAGS (%s)",
			    store->modify_type == MODIFY_ADD ? '+' : '-',
			    store->flags);
		exmdbc_sync_cmd_full(ctx, str_c(cmd), TRUE);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&ctx->stores);
}

static void exmdbc_sync_add_missing_deleted_flags(struct exmdbc_sync_context *ctx, uint32_t seq1, uint32_t seq2) {
	fprintf(stdout, "!!! exmdbc_sync_add_missing_deleted_flags called\n");
	const struct mail_index_record *rec;
	uint32_t seq, uid1, uid2;

	/* if any of them has a missing \Deleted flag,
	   just add it to all of them. */
	for (seq = seq1; seq <= seq2; seq++) {
		rec = mail_index_lookup(ctx->sync_view, seq);
		if ((rec->flags & MAIL_DELETED) == 0)
			break;
	}

	if (seq <= seq2) {
		mail_index_lookup_uid(ctx->sync_view, seq1, &uid1);
		mail_index_lookup_uid(ctx->sync_view, seq2, &uid2);

		exmdbc_sync_store(ctx, MODIFY_ADD, uid1, uid2, "\\Deleted");
	}
}

static void exmdbc_sync_index_flags(struct exmdbc_sync_context *ctx, const struct mail_index_sync_rec *sync_rec) {
	fprintf(stdout, "!!! exmdbc_sync_index_flags called\n");
	string_t *str = t_str_new(128);

	i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);

	if (sync_rec->add_flags != 0) {
		i_assert((sync_rec->add_flags & MAIL_RECENT) == 0);
		//TODO:EXMDBC:
		//imap_write_flags(str, sync_rec->add_flags, NULL);
		exmdbc_sync_store(ctx, MODIFY_ADD, sync_rec->uid1,
				 sync_rec->uid2, str_c(str));
	}

	if (sync_rec->remove_flags != 0) {
		i_assert((sync_rec->remove_flags & MAIL_RECENT) == 0);
		str_truncate(str, 0);
		//imap_write_flags(str, sync_rec->remove_flags, NULL);
		exmdbc_sync_store(ctx, MODIFY_REMOVE, sync_rec->uid1,
				 sync_rec->uid2, str_c(str));
	}
}

static void exmdbc_sync_index_keyword(struct exmdbc_sync_context *ctx, const struct mail_index_sync_rec *sync_rec) {
	fprintf(stdout, "!!! exmdbc_sync_index_keyword called\n");
	const char *kw_str;
	enum modify_type modify_type;

	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		modify_type = MODIFY_ADD;
		break;
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		modify_type = MODIFY_REMOVE;
		break;
	default:
		i_unreached();
	}

	kw_str = array_idx_elem(ctx->keywords, sync_rec->keyword_idx);
	exmdbc_sync_store(ctx, modify_type, sync_rec->uid1,
			 sync_rec->uid2, kw_str);
}

static void exmdbc_sync_expunge_finish(struct exmdbc_sync_context *ctx) {
	fprintf(stdout, "!!! exmdbc_sync_expunge_finish called\n");
	string_t *str;

	if (array_count(&ctx->expunged_uids) == 0)
		return;
//TODO:EXMDBC:
//	if ((ctx->mbox->capabilities & IMAPC_CAPABILITY_UIDPLUS) == 0) {
//		/* just expunge everything */
//		exmdbc_sync_cmd(ctx, "EXPUNGE");
//		return;
//	}

	/* build a list of UIDs to expunge */
	str = t_str_new(128);
	str_append(str, "UID EXPUNGE ");
	//imap_write_seq_range(str, &ctx->expunged_uids);
	exmdbc_sync_cmd(ctx, str_c(str));
}

static void exmdbc_sync_uid_next(struct exmdbc_sync_context *ctx) {
	fprintf(stdout, "!!! exmdbc_sync_uid_next called\n");
	struct exmdbc_mailbox *mbox = ctx->mbox;
	const struct mail_index_header *hdr;
	uint32_t uid_next = mbox->sync_uid_next;

	if (uid_next < mbox->min_append_uid)
		uid_next = mbox->min_append_uid;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->next_uid < uid_next) {
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, next_uid),
			&uid_next, sizeof(uid_next), FALSE);
	}
}

static void exmdbc_sync_highestmodseq(struct exmdbc_sync_context *ctx) {
	fprintf(stdout, "!!! exmdbc_sync_highestmodseq called\n");
	if (exmdbc_mailbox_has_modseqs(ctx->mbox) &&
	    mail_index_modseq_get_highest(ctx->sync_view) < ctx->mbox->sync_highestmodseq)
		mail_index_update_highest_modseq(ctx->trans, ctx->mbox->sync_highestmodseq);
}

static void exmdbc_initial_sync_check(struct exmdbc_sync_context *ctx, bool nooped) {
	fprintf(stdout, "!!! exmdbc_initial_sync_check called\n");

}

static void exmdbc_sync_send_commands(struct exmdbc_sync_context *ctx) {
	fprintf(stdout, "!!! exmdbc_sync_send_commands called\n");

}

static void exmdbc_sync_index(struct exmdbc_sync_context *ctx)
{
	fprintf(stdout, "!!! exmdbc_sync_index called\n");
	struct exmdbc_mailbox *mbox = ctx->mbox;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;

	i_array_init(&ctx->expunged_uids, 64);
	ctx->keywords = mail_index_get_keywords(mbox->box.index);
	ctx->pool = pool_alloconly_create("imapc sync pool", 1024);

	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec)) T_BEGIN {
		if (!mail_index_lookup_seq_range(ctx->sync_view,
						 sync_rec.uid1, sync_rec.uid2,
						 &seq1, &seq2)) {
			/* already expunged, nothing to do. */
		} else switch (sync_rec.type) {
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			exmdbc_sync_add_missing_deleted_flags(ctx, seq1, seq2);
			seq_range_array_add_range(&ctx->expunged_uids,
						  sync_rec.uid1, sync_rec.uid2);
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
			exmdbc_sync_index_flags(ctx, &sync_rec);
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
			exmdbc_sync_index_keyword(ctx, &sync_rec);
			break;
		}
	} T_END;
	exmdbc_sync_finish_store(ctx);
	pool_unref(&ctx->pool);

	if (!mbox->initial_sync_done)
		exmdbc_sync_send_commands(ctx);

	exmdbc_sync_expunge_finish(ctx);
	while (ctx->sync_command_count > 0)
		exmdbc_mailbox_run(mbox);
	array_free(&ctx->expunged_uids);

	if (!mbox->state_fetched_success) {
		/* All the sync commands succeeded, but we got disconnected.
		   imapc_initial_sync_check() will crash if we go there. */
		ctx->failed = TRUE;
	}

	/* add uidnext & highestmodseq after all appends */
	exmdbc_sync_uid_next(ctx);
	exmdbc_sync_highestmodseq(ctx);

	mailbox_sync_notify(&mbox->box, 0, 0);

	if (!ctx->failed) {
		/* reset only after a successful sync */
		mbox->sync_fetch_first_uid = 0;
	}
	if (!mbox->initial_sync_done && !ctx->failed) {
		exmdbc_initial_sync_check(ctx, FALSE);
		mbox->initial_sync_done = TRUE;
	}
}

static int exmdbc_sync_begin(struct exmdbc_mailbox *mbox, struct exmdbc_sync_context **ctx_r, bool force) {
	fprintf(stdout, "!!! exmdbc_sync_begin called\n");
	struct exmdbc_sync_context *ctx;
	enum mail_index_sync_flags sync_flags;
	int ret;

	i_assert(!mbox->syncing);

	ctx = i_new(struct exmdbc_sync_context, 1);
	ctx->mbox = mbox;

	sync_flags = index_storage_get_sync_flags(&mbox->box) |
		MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY;
	if (!force)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;

	ret = mail_index_sync_begin(mbox->box.index, &ctx->index_sync_ctx,
				    &ctx->sync_view, &ctx->trans,
				    sync_flags);
	if (ret <= 0) {
		if (ret < 0)
			mailbox_set_index_error(&mbox->box);
		i_free(ctx);
		*ctx_r = NULL;
		return ret;
	}

	i_assert(mbox->sync_view == NULL);
	i_assert(mbox->delayed_sync_trans == NULL);
	mbox->sync_view = ctx->sync_view;
	mbox->delayed_sync_view =
		mail_index_transaction_open_updated_view(ctx->trans);
	mbox->delayed_sync_trans = ctx->trans;
	mbox->delayed_sync_cache_view =
		mail_cache_view_open(mbox->box.cache, mbox->delayed_sync_view);
	mbox->delayed_sync_cache_trans =
		mail_cache_get_transaction(mbox->delayed_sync_cache_view,
					   mbox->delayed_sync_trans);
	mbox->min_append_uid = mail_index_get_header(ctx->sync_view)->next_uid;

	mbox->syncing = TRUE;
	mbox->sync_ctx = ctx;

	if (mbox->delayed_untagged_exists) {
		bool fetch_send = exmdbc_mailbox_fetch_state(mbox,
							    mbox->min_append_uid);
		while (fetch_send && mbox->delayed_untagged_exists)
			exmdbc_mailbox_run(mbox);
	}

	if (!mbox->box.deleting)
		exmdbc_sync_index(ctx);

	mail_index_view_close(&mbox->delayed_sync_view);
	mbox->delayed_sync_trans = NULL;
	mbox->sync_view = NULL;

	*ctx_r = ctx;
	return 0;
}

static int exmdbc_sync_finish(struct exmdbc_sync_context **_ctx)
{
	fprintf(stdout, "!!! exmdbc_sync_finish called\n");

}

static int exmdbc_untagged_fetch_uid_cmp(struct exmdbc_untagged_fetch_ctx *const *ctx1,
					struct exmdbc_untagged_fetch_ctx *const *ctx2)
{
	fprintf(stdout, "!!! exmdbc_untagged_fetch_uid_cmp called\n");

}

static void exmdbc_sync_handle_untagged_fetches(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_sync_handle_untagged_fetches called\n");

}

static int exmdbc_sync(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_sync called\n");

	return 0;
}

static void exmdbc_noop_if_needed(struct exmdbc_mailbox *mbox, enum mailbox_sync_flags flags)
{
	fprintf(stdout, "!!! exmdbc_noop_if_needed called\n");

}

static bool exmdbc_mailbox_need_initial_fetch(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_need_initial_fetch called\n");
	return TRUE;
}

struct mailbox_sync_context * exmdbc_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	fprintf(stdout, "!!! exmdbc_mailbox_sync_init called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(box);
	struct exmdbc_mailbox_list *list = mbox->storage->client->_list;
	bool changes;
	int ret = 0;

	if (list != NULL) {
		if (!list->refreshed_mailboxes &&
		    list->last_refreshed_mailboxes < ioloop_time)
			list->refreshed_mailboxes_recently = FALSE;
	}

	exmdbc_noop_if_needed(mbox, flags);

	if (!mbox->state_fetched_success && !mbox->state_fetching_uid1 &&
		 exmdbc_mailbox_need_initial_fetch(mbox)) {
		/* initial FETCH failed already */
		ret = -1;
	}
	if (exmdbc_mailbox_commit_delayed_trans(mbox, FALSE, &changes) < 0)
		ret = -1;
	if ((changes || mbox->sync_fetch_first_uid != 0 ||
	     index_mailbox_want_full_sync(&mbox->box, flags)) &&
	    ret == 0)
		ret = exmdbc_sync(mbox);

	return index_mailbox_sync_init(box, flags, ret < 0);
}

int exmdbc_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
			      struct mailbox_sync_status *status_r)
{
	fprintf(stdout, "!!! exmdbc_mailbox_sync_deinit called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(ctx->box);
	int ret;

	ret = index_mailbox_sync_deinit(ctx, status_r);
	ctx = NULL;

	if (mbox->client_box == NULL)
		return ret;

	//TODO:EXMDBC:
	//exmdbc_client_mailbox_idle(mbox->client_box);
	return ret;
}
