#ifndef EXMDBC_SEARCH_H
#define EXMDBC_SEARCH_H

#include "index-mail.h"

struct mail_search_context *
exmdbc_search_init(struct mailbox_transaction_context *t,
		  struct mail_search_args *args,
		  const enum mail_sort_type *sort_program,
		  enum mail_fetch_field wanted_fields,
		  struct mailbox_header_lookup_ctx *wanted_headers);
bool exmdbc_search_next_update_seq(struct mail_search_context *ctx);
int exmdbc_search_deinit(struct mail_search_context *ctx);

#endif
