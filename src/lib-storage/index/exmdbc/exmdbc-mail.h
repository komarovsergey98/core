#ifndef EXMDBC_MAIL_H
#define EXMDBC_MAIL_H

#include "index-mail.h"

struct exmdbc_arg;
struct exmdbc_untagged_reply;
struct exmdbc_mailbox;

struct exmdbc_mail {
	struct index_mail imail;

	enum mail_fetch_field fetching_fields;
	const char *const *fetching_headers;
	unsigned int fetch_count;
	bool fetch_sent;
	const char *last_fetch_reply;

	int fd;
	buffer_t *body;
	bool header_fetched;
	bool body_fetched;
	bool header_list_fetched;
	bool fetch_ignore_if_missing;
	bool fetch_failed;
};

#define EXMDBC_MAIL(s) container_of(s, struct exmdbc_mail, imail.mail.mail)

extern struct mail_vfuncs exmdbc_mail_vfuncs;

struct mail *
exmdbc_mail_alloc(struct mailbox_transaction_context *t,
                  enum mail_fetch_field wanted_fields,
                  struct mailbox_header_lookup_ctx *wanted_headers);
int exmdbc_mail_fetch(struct mail *mail, enum mail_fetch_field fields,
			 const char *const *headers);
void exmdbc_mail_try_init_stream_from_cache(struct exmdbc_mail *mail);
bool exmdbc_mail_prefetch(struct mail *mail);
void exmdbc_mail_fetch_flush(struct exmdbc_mailbox *mbox);
void exmdbc_mail_init_stream(struct exmdbc_mail *mail);
bool exmdbc_mail_has_headers_in_cache(struct index_mail *mail,
					 struct mailbox_header_lookup_ctx *headers);

void exmdbc_mail_fetch_update(struct exmdbc_mail *mail,
				 const struct exmdbc_untagged_reply *reply,
				 const struct exmdbc_arg *args);
void exmdbc_mail_update_access_parts(struct index_mail *mail);
void exmdbc_mail_command_flush(struct exmdbc_mailbox *mbox);

#endif
