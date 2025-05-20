#ifndef EXMDBC_MSGMAP_H
#define EXMDBC_MSGMAP_H

struct exmdbc_msgmap *exmdbc_msgmap_init(void);
void exmdbc_msgmap_deinit(struct exmdbc_msgmap **msgmap);

uint32_t exmdbc_msgmap_count(struct exmdbc_msgmap *msgmap);
uint32_t exmdbc_msgmap_uidnext(struct exmdbc_msgmap *msgmap);
uint32_t exmdbc_msgmap_rseq_to_uid(struct exmdbc_msgmap *msgmap, uint32_t rseq);
bool exmdbc_msgmap_uid_to_rseq(struct exmdbc_msgmap *msgmap,
			      uint32_t uid, uint32_t *rseq_r);

void exmdbc_msgmap_append(struct exmdbc_msgmap *msgmap,
			 uint32_t rseq, uint32_t uid);
void exmdbc_msgmap_expunge(struct exmdbc_msgmap *msgmap, uint32_t rseq);
void exmdbc_msgmap_reset(struct exmdbc_msgmap *msgmap);

#endif
