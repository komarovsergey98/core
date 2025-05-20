/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "exmdbc-msgmap.h"
#include "sort.h"

struct exmdbc_msgmap {
	ARRAY_TYPE(uint32_t) uids;
	uint32_t uid_next;
};

struct exmdbc_msgmap *exmdbc_msgmap_init(void)
{
	struct exmdbc_msgmap *msgmap;

	msgmap = i_new(struct exmdbc_msgmap, 1);
	i_array_init(&msgmap->uids, 128);
	msgmap->uid_next = 1;
	return msgmap;
}

void exmdbc_msgmap_deinit(struct exmdbc_msgmap **_msgmap)
{
	struct exmdbc_msgmap *msgmap = *_msgmap;

	*_msgmap = NULL;

	array_free(&msgmap->uids);
	i_free(msgmap);
}

uint32_t exmdbc_msgmap_count(struct exmdbc_msgmap *msgmap)
{
	return array_count(&msgmap->uids);
}

uint32_t exmdbc_msgmap_uidnext(struct exmdbc_msgmap *msgmap)
{
	return msgmap->uid_next;
}

uint32_t exmdbc_msgmap_rseq_to_uid(struct exmdbc_msgmap *msgmap, uint32_t rseq)
{
	const uint32_t *uidp;

	uidp = array_idx(&msgmap->uids, rseq-1);
	return *uidp;
}

bool exmdbc_msgmap_uid_to_rseq(struct exmdbc_msgmap *msgmap,
			      uint32_t uid, uint32_t *rseq_r)
{
	const uint32_t *p, *first;

	p = array_bsearch(&msgmap->uids, &uid, uint32_cmp);
	if (p == NULL) {
		*rseq_r = 0;
		return FALSE;
	}

	first = array_front(&msgmap->uids);
	*rseq_r = (p - first) + 1;
	return TRUE;
}

void exmdbc_msgmap_append(struct exmdbc_msgmap *msgmap,
			 uint32_t rseq, uint32_t uid)
{
	i_assert(rseq == exmdbc_msgmap_count(msgmap) + 1);
	i_assert(uid >= msgmap->uid_next);

	msgmap->uid_next = uid + 1;
	array_push_back(&msgmap->uids, &uid);
}

void exmdbc_msgmap_expunge(struct exmdbc_msgmap *msgmap, uint32_t rseq)
{
	i_assert(rseq > 0);
	i_assert(rseq <= exmdbc_msgmap_count(msgmap));

	array_delete(&msgmap->uids, rseq-1, 1);
}

void exmdbc_msgmap_reset(struct exmdbc_msgmap *msgmap)
{
	array_clear(&msgmap->uids);
	msgmap->uid_next = 1;
}
