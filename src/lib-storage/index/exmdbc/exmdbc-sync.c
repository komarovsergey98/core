/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mail-index-modseq.h"
#include "index-sync-private.h"
#include "exmdbc-mailbox.h"
#include "exmdbc-storage.h"
#include "exmdbc-sync.h"

#include <exmdb_client_c.h>
#include <stdio.h>


static int find_uid_in_array(uint32_t uid, uint32_t *array, uint32_t size) {
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
