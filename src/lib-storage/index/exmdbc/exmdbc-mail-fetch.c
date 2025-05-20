/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include <stdio.h>

#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-concat.h"
#include "istream-header-filter.h"
#include "message-header-parser.h"
#include "exmdbc-mail.h"
#include "exmdbc-storage.h"
#include "exmdbc-mailbox.h"
#include "exmdbc-mail.h"

static void exmdbc_mail_set_failure(struct exmdbc_mail *mail,
				   const struct exmdbc_command_reply *reply) {
	fprintf(stdout, "!!! exmdbc_mail_set_failure called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(mail->imail.mail.mail.box);

	mail->last_fetch_reply = p_strdup(mail->imail.mail.pool, reply->text_full);
}

static bool
headers_have_subset(const char *const *superset, const char *const *subset)
{
	fprintf(stdout, "!!! headers_have_subset called\n");
	unsigned int i;

	if (superset == NULL)
		return FALSE;
	if (subset != NULL) {
		for (i = 0; subset[i] != NULL; i++) {
			if (!str_array_icase_find(superset, subset[i]))
				return FALSE;
		}
	}
	return TRUE;
}

static const char *const *
headers_merge(pool_t pool, const char *const *h1, const char *const *h2)
{
	fprintf(stdout, "!!! headers_merge called\n");
	ARRAY_TYPE(const_string) headers;
	const char *value;
	unsigned int i;

	p_array_init(&headers, pool, 16);
	if (h1 != NULL) {
		for (i = 0; h1[i] != NULL; i++) {
			value = p_strdup(pool, h1[i]);
			array_push_back(&headers, &value);
		}
	}
	if (h2 != NULL) {
		for (i = 0; h2[i] != NULL; i++) {
			if (h1 == NULL || !str_array_icase_find(h1, h2[i])) {
				value = p_strdup(pool, h2[i]);
				array_push_back(&headers, &value);
			}
		}
	}
	array_append_zero(&headers);
	return array_front(&headers);
}

static bool
exmdbc_mail_try_merge_fetch(struct exmdbc_mailbox *mbox, string_t *str)
{
	fprintf(stdout, "!!! exmdbc_mail_try_merge_fetch called\n");
	const char *s1 = str_c(str);
	const char *s2 = str_c(mbox->pending_fetch_cmd);
	const char *s1_args, *s2_args, *p1, *p2;

	if (!str_begins(s1, "UID FETCH ", &s1_args))
		i_unreached();
	if (!str_begins(s2, "UID FETCH ", &s2_args))
		i_unreached();

	/* skip over UID range */
	p1 = strchr(s1_args, ' ');
	p2 = strchr(s2_args, ' ');

	if (null_strcmp(p1, p2) != 0)
		return FALSE;
	/* append the new UID to the pending FETCH UID range */
	str_truncate(str, p1-s1);
	str_insert(mbox->pending_fetch_cmd, p2-s2, ",");
	str_insert(mbox->pending_fetch_cmd, p2-s2+1, str_c(str) + 10);
	return TRUE;
}

static void
exmdbc_mail_delayed_send_or_merge(struct exmdbc_mail *mail, string_t *str)
{
	fprintf(stdout, "!!! exmdbc_mail_delayed_send_or_merge called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(mail->imail.mail.mail.box);

	if (mbox->pending_fetch_request != NULL &&
	    !exmdbc_mail_try_merge_fetch(mbox, str)) {
		/* send the previous FETCH and create a new one */
		exmdbc_mail_fetch_flush(mbox);
	}
	if (mbox->pending_fetch_request == NULL) {
		mbox->pending_fetch_request =
			i_new(struct exmdbc_fetch_request, 1);
		i_array_init(&mbox->pending_fetch_request->mails, 4);
		i_assert(mbox->pending_fetch_cmd->used == 0);
		str_append_str(mbox->pending_fetch_cmd, str);
	}
	array_push_back(&mbox->pending_fetch_request->mails, &mail);

	if (mbox->to_pending_fetch_send == NULL &&
	    array_count(&mbox->pending_fetch_request->mails) >
	    			mbox->box.storage->set->mail_prefetch_count) {
		/* we're now prefetching the maximum number of mails. this
		   most likely means that we need to flush out the command now
		   before sending anything else. delay it a little bit though
		   in case the sending code doesn't actually use
		   mail_prefetch_count and wants to fetch more.

		   note that we don't want to add this timeout too early,
		   because we want to optimize the maximum number of messages
		   placed into a single FETCH. even without timeout the command
		   gets flushed by exmdbc_mail_fetch() call. */
		mbox->to_pending_fetch_send =
			timeout_add_short(0, exmdbc_mail_fetch_flush, mbox);
	}
}

static int
exmdbc_mail_send_fetch(struct mail *_mail, enum mail_fetch_field fields,
		      const char *const *headers)
{
	fprintf(stdout, "!!! exmdbc_mail_send_fetch called\n");
	struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct mail_index_view *view;
	string_t *str;
	uint32_t seq;
	unsigned int i;

	//TODO:EXMDBC:

	str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');

	mail->fetching_fields |= fields;
	mail->fetch_count++;
	mail->fetch_sent = FALSE;
	mail->fetch_failed = FALSE;

	exmdbc_mail_delayed_send_or_merge(mail, str);
	return 1;
}

static void exmdbc_mail_cache_get(struct exmdbc_mail *mail,
				 struct exmdbc_mail_cache *cache)
{
	fprintf(stdout, "!!! exmdbc_mail_cache_get called\n");
	if (mail->body_fetched)
		return;

	if (cache->fd != -1) {
		mail->fd = cache->fd;
		mail->imail.data.stream = i_stream_create_fd(mail->fd, 0);
		cache->fd = -1;
	} else if (cache->buf != NULL) {
		mail->body = cache->buf;
		mail->imail.data.stream =
			i_stream_create_from_data(mail->body->data,
						  mail->body->used);
		cache->buf = NULL;
	} else {
		return;
	}
	mail->header_fetched = TRUE;
	mail->body_fetched = TRUE;
	/* The stream was already accessed and now it's cached.
	   It still needs to be set accessed to avoid assert-crash. */
	mail->imail.mail.mail.mail_stream_accessed = TRUE;
	exmdbc_mail_init_stream(mail);
}

static enum mail_fetch_field
exmdbc_mail_get_wanted_fetch_fields(struct exmdbc_mail *mail)
{
	fprintf(stdout, "!!! exmdbc_mail_get_wanted_fetch_fields called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(mail->imail.mail.mail.box);
	struct index_mail_data *data = &mail->imail.data;
	enum mail_fetch_field fields = 0;


	//TODO:EXMDBC:
	return fields;
}

void exmdbc_mail_try_init_stream_from_cache(struct exmdbc_mail *mail)
{
	fprintf(stdout, "!!! exmdbc_mail_try_init_stream_from_cache called\n");
	struct mail *_mail = &mail->imail.mail.mail;
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);

	if (mbox->prev_mail_cache.uid == _mail->uid)
		exmdbc_mail_cache_get(mail, &mbox->prev_mail_cache);
}

bool exmdbc_mail_prefetch(struct mail *_mail)
{
	fprintf(stdout, "!!! exmdbc_mail_prefetch called\n");
	struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct index_mail_data *data = &mail->imail.data;
	enum mail_fetch_field fields;

	//TODO:EXMDBC:
	return !mail->imail.data.prefetch_sent;
}

static bool
exmdbc_mail_have_fields(struct exmdbc_mail *imail, enum mail_fetch_field fields)
{
	fprintf(stdout, "!!! exmdbc_mail_have_fields called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(imail->imail.mail.mail.box);


	//TODO:EXMDBC:
	return TRUE;
}

int exmdbc_mail_fetch(struct mail *_mail, enum mail_fetch_field fields,
		     const char *const *headers)
{
	fprintf(stdout, "!!! exmdbc_mail_fetch called\n");
	struct exmdbc_mail *imail = EXMDBC_MAIL(_mail);
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	int ret;

	if ((fields & MAIL_FETCH_GUID) != 0 &&
	    mbox->guid_fetch_field_name == NULL) {
		mail_storage_set_error(_mail->box->storage,
			MAIL_ERROR_NOTPOSSIBLE,
			"Message GUID not available in this server");
		return -1;
	}
	if (_mail->saving) {
		mail_storage_set_error(_mail->box->storage,
			MAIL_ERROR_NOTPOSSIBLE,
			"Attempting to issue FETCH for a mail not yet committed");
		return -1;
	}

	fields |= exmdbc_mail_get_wanted_fetch_fields(imail);
	T_BEGIN {
		ret = exmdbc_mail_send_fetch(_mail, fields, headers);
	} T_END;
	if (ret < 0)
		return -1;

	/* we'll continue waiting until we've got all the fields we wanted,
	   or until all FETCH replies have been received (i.e. some FETCHes
	   failed) */
	if (ret > 0)
		exmdbc_mail_fetch_flush(mbox);
	while (imail->fetch_count > 0 &&
	       (!exmdbc_mail_have_fields(imail, fields) ||
		!imail->header_list_fetched)) {
		exmdbc_mailbox_run_nofetch(mbox);
	}
	if (imail->fetch_failed) {
		mail_storage_set_internal_error(&mbox->storage->storage);
		return -1;
	}
	return 0;
}

void exmdbc_mail_fetch_flush(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mail_fetch_flush called\n");
	struct exmdbc_command *cmd;
	struct exmdbc_mail *mail;

	if (mbox->pending_fetch_request == NULL) {
		i_assert(mbox->to_pending_fetch_send == NULL);
		return;
	}

	array_foreach_elem(&mbox->pending_fetch_request->mails, mail)
		mail->fetch_sent = TRUE;

	//TODO:EXMDBC:

	mbox->pending_fetch_request = NULL;
	timeout_remove(&mbox->to_pending_fetch_send);
	str_truncate(mbox->pending_fetch_cmd, 0);
}

static bool exmdbc_find_lfile_arg(const struct exmdbc_untagged_reply *reply,
				 const struct exmdbc_arg *arg, int *fd_r)
{
	fprintf(stdout, "!!! exmdbc_find_lfile_arg called\n");
	const struct exmdbc_arg *list;
	unsigned int i, count;

	for (i = 0; i < reply->file_args_count; i++) {
		const struct exmdbc_arg_file *farg = &reply->file_args[i];

		//TODO:EXMDBC:
		// if (farg->parent_arg == arg->parent &&
		//     exmdbc_arg_get_list_full(arg->parent, &list, &count) &&
		//     farg->list_idx < count && &list[farg->list_idx] == arg) {
		// 	*fd_r = farg->fd;
		// 	return TRUE;
		// }
	}
	return FALSE;
}

static void exmdbc_stream_filter(struct istream **input)
{
	fprintf(stdout, "!!! exmdbc_stream_filter called\n");
	static const char *exmdbc_hide_headers[] = {
		/* Added by MS Exchange 2010 when \Flagged flag is set.
		   This violates IMAP guarantee of messages being immutable. */
		"X-Message-Flag"
	};
	struct istream *filter_input;

	filter_input = i_stream_create_header_filter(*input,
		HEADER_FILTER_EXCLUDE,
		exmdbc_hide_headers, N_ELEMENTS(exmdbc_hide_headers),
		*null_header_filter_callback, NULL);
	i_stream_unref(input);
	*input = filter_input;
}

void exmdbc_mail_init_stream(struct exmdbc_mail *mail)
{
	fprintf(stdout, "!!! exmdbc_mail_init_stream called\n");
	struct index_mail *imail = &mail->imail;
	struct mail *_mail = &imail->mail.mail;
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct istream *input;
	uoff_t size;
	int ret;

	i_stream_set_name(imail->data.stream,
			  t_strdup_printf("exmdbc mail uid=%u", _mail->uid));
	index_mail_set_read_buffer_size(_mail, imail->data.stream);

	//TODO:EXMDBC:
}

static void
exmdbc_fetch_stream(struct exmdbc_mail *mail,
		   const struct exmdbc_untagged_reply *reply,
		   const struct exmdbc_arg *arg,
		   bool have_header, bool have_body)
{
	fprintf(stdout, "!!! exmdbc_fetch_stream called\n");
	struct index_mail *imail = &mail->imail;
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(imail->mail.mail.box);
	struct event *event = mbox->box.event;
	struct istream *hdr_stream = NULL;
	const char *value;
	int fd;

	//TODO:EXMDBC:
	exmdbc_mail_init_stream(mail);
}

static void
exmdbc_fetch_header_stream(struct exmdbc_mail *mail,
			  const struct exmdbc_untagged_reply *reply,
			  const struct exmdbc_arg *args)
{
	fprintf(stdout, "!!! exmdbc_fetch_header_stream called\n");
	const enum message_header_parser_flags hdr_parser_flags =
		MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP |
		MESSAGE_HEADER_PARSER_FLAG_DROP_CR;
	const struct exmdbc_arg *hdr_list;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct istream *input;
	ARRAY_TYPE(const_string) hdr_arr;
	const char *value;
	int ret, fd;

	//TODO:EXMDBC:

	headers_ctx = mailbox_header_lookup_init(mail->imail.mail.mail.box,
						 array_front(&hdr_arr));
	index_mail_parse_header_init(&mail->imail, headers_ctx);

	parser = message_parse_header_init(input, NULL, hdr_parser_flags);
	while ((ret = message_parse_header_next(parser, &hdr)) > 0) T_BEGIN {
		index_mail_parse_header(NULL, hdr, &mail->imail);
	} T_END;
	i_assert(ret != 0);
	index_mail_parse_header(NULL, NULL, &mail->imail);
	message_parse_header_deinit(&parser);

	mailbox_header_lookup_unref(&headers_ctx);
	i_stream_destroy(&input);
}

static const char *
exmdbc_args_to_bodystructure(struct exmdbc_mail *mail,
			    const struct exmdbc_arg *list_arg, bool extended)
{
	fprintf(stdout, "!!! exmdbc_args_to_bodystructure called\n");
	const struct exmdbc_arg *args;
	struct message_part *parts = NULL;
	const char *ret, *error;
	pool_t pool;

	//TODO:EXMDBC:
	pool_unref(&pool);
	return ret;
}

void exmdbc_mail_fetch_update(struct exmdbc_mail *mail,
			     const struct exmdbc_untagged_reply *reply,
			     const struct exmdbc_arg *args)
{
	fprintf(stdout, "!!! exmdbc_mail_fetch_update called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(mail->imail.mail.mail.box);
	const char *key, *value;
	unsigned int i;
	uoff_t size;
	time_t t;
	int tz;
	bool match = FALSE;

	//TODO:EXMDBC:
}
