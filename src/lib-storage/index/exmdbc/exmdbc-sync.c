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

#include <exmdb_client_c.h>
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

static int find_uid_in_array(uint64_t uid, uint64_t *array, int size) {
	for (int i = 0; i < size; ++i)
		if (array[i] == uid)
			return i;
	return -1;
}

int exmdbc_mailbox_sync(struct exmdbc_mailbox *mbox)
{
    fprintf(stdout, "!!! exmdbc_sync called\n");
    struct mail_index_view *view = mbox->box.view;
    struct mail_index_transaction *trans = mail_index_transaction_begin(view, 0);

    const struct mail_index_header *hdr = mail_index_get_header(view);
	bool index_is_empty = (hdr->uid_validity == 0);
    bool full_resync = false;

	if (index_is_empty) {
		uint32_t uidvalid = (uint32_t)mbox->folder_id;
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uidvalid, sizeof(uidvalid), TRUE);
	}

	if (hdr->uid_validity != (uint32_t)mbox->folder_id) {
		mail_index_reset(trans);
		full_resync = true;
	}

    unsigned int max_messages = 1000;
    struct folder_metadata_message *messages = calloc(max_messages, sizeof(*messages));
    if (!messages) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    const char *username = mbox->box.list->ns->user->username;
    int gromox_count = exmdbc_client_get_folder_messages(
        mbox->storage->client->client,
        mbox->folder_id, messages,
        max_messages, username, 0
    );
    if (gromox_count < 0) {
        fprintf(stderr, "Failed to get folder messages\n");
        free(messages);
        return 1;
    }

    // UID from gromox
    uint32_t max_uid_from_rpc = 0;
    uint32_t *gromox_uids = calloc(gromox_count, sizeof(uint32_t));
    for (int i = 0; i < gromox_count; ++i) {
        uint32_t uid = (uint32_t)messages[i].mid;
        gromox_uids[i] = uid;
        if (uid > max_uid_from_rpc)
            max_uid_from_rpc = uid;
    }
    uint32_t next_uid = max_uid_from_rpc + 1;

    // UID from fovecot
    uint32_t index_count = mail_index_view_get_messages_count(view);
    uint32_t *index_uids = calloc(index_count, sizeof(uint32_t));
    for (uint32_t lseq = 1; lseq <= index_count; ++lseq) {
        uint32_t uid;
        mail_index_lookup_uid(view, lseq, &uid);
        index_uids[lseq - 1] = uid;
    }

    // Expunge UID
    for (uint32_t lseq = 1; lseq <= index_count; ++lseq) {
        uint32_t uid;
        mail_index_lookup_uid(view, lseq, &uid);
        if (find_uid_in_array(uid, gromox_uids, gromox_count) < 0) {
            mail_index_expunge(trans, lseq);
        }
    }

    // Add UID
    for (int i = 0; i < gromox_count; ++i) {
        uint32_t mid = gromox_uids[i];
        // full resync
        if (find_uid_in_array(mid, index_uids, index_count) < 0 &&
            (full_resync || mid >= hdr->next_uid)) {
            uint32_t lseq;
            mail_index_append(trans, mid, &lseq);
            mail_index_update_flags(trans, lseq, MODIFY_ADD, messages[i].flags);
            fprintf(stderr, "[EXMDBC] New index was added -> lseq=%u, uid=%u\n", lseq, mid);
        }
    }

    // Update flags
    for (int i = 0; i < gromox_count; ++i) {
        uint32_t lseq;
        if (mail_index_lookup_seq(view, gromox_uids[i], &lseq)) {
            mail_index_update_flags(trans, lseq, MODIFY_REPLACE, messages[i].flags);
        }
    }

    if (full_resync) {
        uint32_t uidvalid = (uint32_t)mbox->folder_id;
        mail_index_update_header(trans,
            offsetof(struct mail_index_header, uid_validity),
            &uidvalid, sizeof(uidvalid), TRUE);
    }

    mail_index_update_header(trans,
        offsetof(struct mail_index_header, next_uid),
        &next_uid, sizeof(next_uid), FALSE);

    mail_index_transaction_commit(&trans);

    free(gromox_uids);
    free(index_uids);
    free(messages);

    return 0;
}


static bool exmdbc_mailbox_need_initial_fetch(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_need_initial_fetch called\n");
	if (mbox->box.deleting) {
		/* If the mailbox is about to be deleted there is no need to
		   expect initial fetch to be done */
		return FALSE;
	}
	if ((mbox->box.flags & MAILBOX_FLAG_SAVEONLY) != 0) {
		/* The mailbox is opened only for saving there is no need to
		   expect initial fetching do be done. */
		return FALSE;
	}
	return TRUE;
}

static int exmdbc_sync_run(struct maildir_mailbox *mbox,
				enum mailbox_sync_flags flags, bool force_resync,
				uint32_t *uid, bool *lost_files_r)
{
	// struct exmdbc_sync_context *ctx;
	// bool retry, lost_files;
	// int ret;
	//
	// T_BEGIN {
	// 	ctx = maildir_sync_context_new(mbox, flags);
	// 	ret = maildir_sync_context(ctx, force_resync, uid, lost_files_r);
	// 	retry = ctx->racing;
	// 	maildir_sync_deinit(ctx);
	// } T_END;
	//
	// if (retry) T_BEGIN {
	// 	/* we're racing some file. retry the sync again to see if the
	// 	   file is really gone or not. if it is, this is a bit of
	// 	   unnecessary work, but if it's not, this is necessary for
	// 	   e.g. doveadm force-resync to work. */
	// 	ctx = maildir_sync_context_new(mbox, 0);
	// 	ret = maildir_sync_context(ctx, TRUE, NULL, &lost_files);
	// 	maildir_sync_deinit(ctx);
	// } T_END;
	// return ret;
}

struct mailbox_sync_context * exmdbc_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	fprintf(stdout, "!!! exmdbc_mailbox_sync_init called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(box);
	struct exmdbc_mailbox_list *list = mbox->storage->client->_list;
	int ret = 0;

	if (index_mailbox_want_full_sync(&mbox->box, flags)) {
		struct exmdbc_mailbox_list_iterate_context *ctx =
			p_new(list->list.pool, struct exmdbc_mailbox_list_iterate_context, 1);

		ctx->ctx.pool = list->list.pool;
		ctx->ctx.list = box->list;
		ctx->ctx.flags = 0;
		ctx->next_index = 0;

		array_create(&ctx->ctx.module_contexts, list->list.pool, sizeof(void *), 5);
		if (exmdbc_list_refresh(list, ctx) < 0) {
			mail_storage_set_internal_error(box->storage);
			return NULL;
		}
		ret = exmdbc_mailbox_sync(mbox);
	}

	if (list != NULL) {
		if (!list->refreshed_mailboxes &&
		    list->last_refreshed_mailboxes < ioloop_time)
			list->refreshed_mailboxes_recently = FALSE;
	}

	if (!mbox->state_fetched_success && !mbox->state_fetching_uid1 &&
		 exmdbc_mailbox_need_initial_fetch(mbox)) {
		/* initial FETCH failed already */
		ret = -1;
	}

	return index_mailbox_sync_init(box, flags, ret < 0);
}
