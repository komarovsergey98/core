#include <istream-concat.h>
#include <stdio.h>
#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "istream.h"

#include "exmdbc-mail.h"
#include "exmdbc-storage.h"
#include "exmdbc-mailbox.h"
#include "exmdb_client_c.h"

void exmdbc_mail_fetch_flush(struct exmdbc_mailbox *mbox)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_fetch_flush called (dummy)\n");
    // TODO: Actually trigger a FETCH operation via exmdb_client
}

static char *imap_envelope_address(const char *name, const char *email)
{
	if (!email || !*email)
		return strdup("NIL");

	const char *at = strchr(email, '@');
	if (!at)
		return strdup("NIL");

	size_t local_len = at - email;
	char local[128], domain[128];
	strncpy(local, email, local_len);
	local[local_len] = 0;
	strncpy(domain, at + 1, sizeof(domain) - 1);
	domain[sizeof(domain) - 1] = 0;

	if (name && *name)
		return t_strdup_printf("(\"%s\" NIL \"%s\" \"%s\")", name, local, domain);
	return t_strdup_printf("(NIL NIL \"%s\" \"%s\")", local, domain);
}

static void rfc822_date_string(time_t ts, char *buf, size_t bufsize)
{
	struct tm tm;
	gmtime_r(&ts, &tm);
	strftime(buf, bufsize, "%a, %d %b %Y %H:%M:%S +0000", &tm);
}

static char *form_envelope(const char *from_name, const char *from_email,
						   const char *to_name,   const char *to_email,
						   const char *subject,
						   time_t date,
						   const char *msgid, const char *in_reply_to)
{
	char *from_addr = imap_envelope_address(from_name, from_email);
	char *to_addr   = imap_envelope_address(to_name, to_email);

	char date_str[128] = "";
	rfc822_date_string(date, date_str, sizeof(date_str));

	const char *sender = from_addr;
	const char *reply_to = from_addr;
	const char *cc = "NIL";
	const char *bcc = "NIL";

	char subj_esc[1024];
	if (subject)
		snprintf(subj_esc, sizeof(subj_esc), "%s", subject);
	else
		strcpy(subj_esc, "");

	const char *msgid_final = (msgid && *msgid) ? msgid : "NIL";
	const char *irt_final   = (in_reply_to && *in_reply_to) ? in_reply_to : "NIL";

	char *envelope = t_strdup_printf(
		"(\"%s\" \"%s\" %s %s %s %s %s %s \"%s\" \"%s\")",
		date_str,
		subj_esc,
		from_addr,    // from
		sender,       // sender
		reply_to,     // reply-to
		to_addr,      // to
		cc,           // cc
		bcc,          // bcc
		irt_final,    // in-reply-to
		msgid_final   // message-id
	);

	free(from_addr);
	free(to_addr);
	return envelope;
}

static void
exmdbc_fetch_stream(struct exmdbc_mail *mail, struct message_properties * msg_props)
{
	struct index_mail *imail = &mail->imail;
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(imail->mail.mail.box);
	struct event *event = mbox->box.event;

	struct istream *hdr_stream = NULL;
	struct istream *body_stream = NULL;

	const char *value;
	int fd;

	if (imail->data.stream != NULL) {
		index_mail_close_streams(imail);
	}


	if (msg_props->message_header != NULL) {
		size_t header_len = strlen(msg_props->message_header);
		hdr_stream = i_stream_create_from_data(msg_props->message_header, header_len);
	}
	if (msg_props->body_plain != NULL || msg_props->body_html != NULL) {
		const char *body = msg_props->body_plain ? msg_props->body_plain : msg_props->body_html;
		size_t body_len = strlen(body);
		body_stream = i_stream_create_from_data(body, body_len);
	}
	if (hdr_stream != NULL && body_stream != NULL) {
		struct istream *inputs[3] = { hdr_stream, body_stream, NULL };
		imail->data.stream = i_stream_create_concat(inputs);
		i_stream_unref(&hdr_stream);
		i_stream_unref(&body_stream);
	} else if (hdr_stream != NULL) {
		imail->data.stream = hdr_stream;
	} else if (body_stream != NULL) {
		imail->data.stream = body_stream;
	} else {
		imail->data.stream = NULL;
	}

	mail->header_fetched = msg_props->message_header != NULL;
	mail->body_fetched = msg_props->body_plain != NULL || msg_props->body_html != NULL;
	mail->imail.mail.mail.mail_stream_accessed = TRUE;

	exmdbc_mail_init_stream(mail);

}


static int exmdbc_mail_send_fetch(struct mail *_mail, enum mail_fetch_field fields, const char *const *headers)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_send_fetch called (dummy)\n");

    struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
    struct index_mail *imail = &mail->imail;
    struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct index_mail_data *data = &imail->data;

    uint32_t uid = _mail->uid;

    struct exmdbc_mailbox_list *list = (struct exmdbc_mailbox_list *)mbox->box.list;
    const char *username = list->list.ns->user->username;
    struct message_properties msg_props;

	if (exmdbc_client_get_message_properties(mbox->storage->client->client, mbox->folder_id, uid, username, &msg_props) != 0) {
		fprintf(stderr, "[EXMDBC] exmdbc_mail_send_fetch error occured\n");
		mail->fetch_failed = TRUE;
		return -1;
	}

	if (fields & MAIL_FETCH_FLAGS) {
		//flags already converted
		data->cache_flags = msg_props.flags;
	}

//Size -------------------
	if (fields & MAIL_FETCH_PHYSICAL_SIZE) {
		data->physical_size = msg_props.size;
	}
	if (fields & MAIL_FETCH_VIRTUAL_SIZE) {
		data->virtual_size = msg_props.size;//TODO:EXMDBC Fixme
	}

//Dates----------------
	if (fields & MAIL_FETCH_DATE) {
		data->date = msg_props.submited_time;
	}
	if (fields & MAIL_FETCH_RECEIVED_DATE) {
		data->received_date = msg_props.delivery_time;
	}
	// if (fields & MAIL_FETCH_SAVE_DATE) {
		// data->save_date = msg_props.save_time;
	// }
//-----------------------

	exmdbc_fetch_stream(mail, &msg_props);

	if (fields & MAIL_FETCH_IMAP_ENVELOPE) {
		char *envelope = form_envelope(msg_props.from_name, msg_props.from_email, msg_props.to_name, msg_props.to_email, msg_props.subject,	msg_props.submited_time, msg_props.msg_id, msg_props.reply_to);
		data->envelope = envelope;
	}

	if (msg_props.from_name)
		;
	if (msg_props.to_name)
		;
	if (msg_props.cc)
		;
	if (msg_props.bcc)
		;
	if (msg_props.reply_recipment)
		;
	if (msg_props.reply_to)
		;

	fprintf(stdout, "[EXMDBC] fetched uid=%u subject='%s' flags=0x%x\n",
			uid, msg_props.subject ? msg_props.subject : "(null)", msg_props.flags);

    mail->fetching_fields |= fields;
    // mail->fetch_count++;
    mail->fetch_sent = TRUE;
    mail->fetch_failed = FALSE;

    return 1;
}

// Used internally to check what fields are still missing
static bool exmdbc_mail_have_fields(struct exmdbc_mail *mail, enum mail_fetch_field fields)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_have_fields called (dummy)\n");

    // TODO: Implement proper field tracking
    return TRUE;
}

static enum mail_fetch_field exmdbc_mail_get_wanted_fetch_fields(struct exmdbc_mail *mail)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_get_wanted_fetch_fields called (dummy)\n");

	//TODO: EXMDBC: Need to build additional falg value with all MAPI PR_ flags
	struct index_mail_data *data = &mail->imail.data;
	enum mail_fetch_field fields = 0;

	if ((data->wanted_fields & MAIL_FETCH_FLAGS) != 0)
		fields |= MAIL_FETCH_FLAGS;

	if ((data->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) != 0)
		fields |= MAIL_FETCH_MESSAGE_PARTS;

	if ((data->wanted_fields & MAIL_FETCH_STREAM_HEADER) != 0)
		fields |= MAIL_FETCH_STREAM_HEADER;

	if ((data->wanted_fields & MAIL_FETCH_STREAM_BODY) != 0)
		fields |= MAIL_FETCH_STREAM_BODY;

	//Datetime
	if ((data->wanted_fields & MAIL_FETCH_DATE) != 0 && data->date == (time_t)-1)
		fields |= MAIL_FETCH_DATE;
	if ((data->wanted_fields & MAIL_FETCH_RECEIVED_DATE) != 0 && data->received_date == (time_t)-1)
		fields |= MAIL_FETCH_RECEIVED_DATE;
	if ((data->wanted_fields & MAIL_FETCH_SAVE_DATE) != 0 && data->save_date == (time_t)-1)
		fields |= MAIL_FETCH_SAVE_DATE;

	//Sizes
	if ((data->wanted_fields & MAIL_FETCH_PHYSICAL_SIZE) != 0 && data->physical_size == UOFF_T_MAX)
		fields |= MAIL_FETCH_PHYSICAL_SIZE;
	if ((data->wanted_fields & MAIL_FETCH_VIRTUAL_SIZE) != 0 && data->virtual_size == UOFF_T_MAX)
		fields |= MAIL_FETCH_VIRTUAL_SIZE;

	//Check for nul state
	// if ((data->wanted_fields & MAIL_FETCH_NUL_STATE) != 0)
	// 	fields |= MAIL_FETCH_NUL_STATE;

	//Binary
	if ((data->wanted_fields & MAIL_FETCH_STREAM_BINARY) != 0)
		fields |= MAIL_FETCH_STREAM_BINARY;

	//BODYSTRUCTURE ENVELOPE etc
	if ((data->wanted_fields & MAIL_FETCH_IMAP_BODY) != 0 && data->body == NULL)
		fields |= MAIL_FETCH_IMAP_BODY;
	if ((data->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) != 0 && data->bodystructure == NULL)
		fields |= MAIL_FETCH_IMAP_BODYSTRUCTURE;
	if ((data->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE) != 0 && data->envelope == NULL)
		fields |= MAIL_FETCH_IMAP_ENVELOPE;
	if ((data->wanted_fields & MAIL_FETCH_FROM_ENVELOPE) != 0 && data->from_envelope == NULL)
		fields |= MAIL_FETCH_FROM_ENVELOPE;
	if ((data->wanted_fields & MAIL_FETCH_HEADER_MD5) != 0)
		fields |= MAIL_FETCH_HEADER_MD5;
	if ((data->wanted_fields & MAIL_FETCH_STORAGE_ID) != 0 && data->guid == NULL)
		fields |= MAIL_FETCH_STORAGE_ID;
	if ((data->wanted_fields & MAIL_FETCH_UIDL_BACKEND) != 0)
		fields |= MAIL_FETCH_UIDL_BACKEND;
	if ((data->wanted_fields & MAIL_FETCH_MAILBOX_NAME) != 0)
		fields |= MAIL_FETCH_MAILBOX_NAME;
	if ((data->wanted_fields & MAIL_FETCH_SEARCH_RELEVANCY) != 0)
		fields |= MAIL_FETCH_SEARCH_RELEVANCY;
	if ((data->wanted_fields & MAIL_FETCH_GUID) != 0 && data->guid == NULL)
		fields |= MAIL_FETCH_GUID;
	if ((data->wanted_fields & MAIL_FETCH_POP3_ORDER) != 0)
		fields |= MAIL_FETCH_POP3_ORDER;
	if ((data->wanted_fields & MAIL_FETCH_REFCOUNT) != 0)
		fields |= MAIL_FETCH_REFCOUNT;
	if ((data->wanted_fields & MAIL_FETCH_BODY_SNIPPET) != 0 && data->body_snippet == NULL)
		fields |= MAIL_FETCH_BODY_SNIPPET;
	if ((data->wanted_fields & MAIL_FETCH_REFCOUNT_ID) != 0)
		fields |= MAIL_FETCH_REFCOUNT_ID;


	if (data->stream == NULL && data->access_part != 0) {
		if ((data->access_part & (READ_BODY | PARSE_BODY)) != 0)
			fields |= MAIL_FETCH_STREAM_BODY;
		fields |= MAIL_FETCH_STREAM_HEADER;
	}

	return fields;
}

// This is the main entry point for FETCH
int exmdbc_mail_fetch(struct mail *_mail, enum mail_fetch_field fields, const char *const *headers)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_fetch called\n");

    struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
    struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);

    if (_mail->saving) {
        mail_storage_set_error(_mail->box->storage, MAIL_ERROR_NOTPOSSIBLE, "Can't FETCH uncommitted mail");
        return -1;
    }

    fields |= exmdbc_mail_get_wanted_fetch_fields(mail);

    int ret = 0;
    T_BEGIN {
        ret = exmdbc_mail_send_fetch(_mail, fields, headers);
    } T_END;

    if (ret < 0)
        return -1;

    if (ret > 0)
        exmdbc_mail_fetch_flush(mbox);

    while (mail->fetch_count > 0 &&
           (!exmdbc_mail_have_fields(mail, fields) || !mail->header_list_fetched)) {
        // TODO: Actually process async events
        exmdbc_mailbox_run_nofetch(mbox);
    }

    if (mail->fetch_failed) {
        mail_storage_set_internal_error(&mbox->storage->storage);
        return -1;
    }
    return 0;
}

bool exmdbc_mail_prefetch(struct mail *_mail)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_prefetch called (dummy)\n");

    struct exmdbc_mail *exmdbc_mail = EXMDBC_MAIL(_mail);
    struct index_mail *mail = &exmdbc_mail->imail;
    struct exmdbc_mailbox *mbox = (struct exmdbc_mailbox *)_mail->box;
	struct index_mail_data *data = &mail->data;

    enum mail_fetch_field fields = exmdbc_mail_get_wanted_fetch_fields(exmdbc_mail);
    const char *const *headers = NULL;

    if (data->access_part != 0) {
        exmdbc_mail_try_init_stream_from_cache(mail);
    }

    if (fields != 0 || headers != NULL) T_BEGIN {
        if (exmdbc_mail_send_fetch(_mail, fields, headers) > 0)
            mail->data.prefetch_sent = TRUE;
    } T_END;

    return !mail->data.prefetch_sent;
}

// Stream init (currently dummy)
void exmdbc_mail_init_stream(struct exmdbc_mail *mail)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_init_stream called (dummy)\n");
	struct index_mail *imail = &mail->imail;
	struct mail *_mail = &imail->mail.mail;
	struct imapc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct istream *input;
	uoff_t size;
	int ret;

	i_stream_set_name(imail->data.stream,
			  t_strdup_printf("exmdbc mail uid=%u", _mail->uid));
	index_mail_set_read_buffer_size(_mail, imail->data.stream);

	if (imail->mail.v.istream_opened != NULL) {
		if (imail->mail.v.istream_opened(_mail,
						 &imail->data.stream) < 0) {
			index_mail_close_streams(imail);
			return;
						 }
	}
	ret = i_stream_get_size(imail->data.stream, TRUE, &size);
	if (ret < 0) {
		index_mail_close_streams(imail);
		return;
	}
	i_assert(ret != 0);
	/* Once message body is fetched, we can be sure of what its size is.
	   If we had already received RFC822.SIZE, overwrite it here in case
	   it's wrong. Also in more special cases the RFC822.SIZE may be
	   smaller than the fetched message header. In this case change the
	   size as well, otherwise reading via istream-mail will fail. */
	if (mail->body_fetched || imail->data.physical_size < size) {
		if (mail->body_fetched) {
			imail->data.inexact_total_sizes = FALSE;
			/* Don't trust any existing virtual_size. Also don't
			   set it to size, because there's no guarantees about
			   the content having proper CRLF newlines, especially
			   not if istream_opened() has changed the stream. */
			imail->data.virtual_size = UOFF_T_MAX;
		}
		imail->data.physical_size = size;
	}

	imail->data.stream_has_only_header = !mail->body_fetched;
	if (index_mail_init_stream(imail, NULL, NULL, &input) < 0)
		index_mail_close_streams(imail);
}

static void exmdbc_mail_cache_get(struct exmdbc_mail *mail,
				 struct exmdbc_mail_cache *cache)
{
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

void exmdbc_mail_try_init_stream_from_cache(struct exmdbc_mail *mail)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_try_init_stream_from_cache called\n");

	struct mail *_mail = &mail->imail.mail.mail;
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);

	if (mbox->prev_mail_cache.uid == _mail->uid)
		exmdbc_mail_cache_get(mail, &mbox->prev_mail_cache);
}

void exmdbc_mail_fetch_update(struct exmdbc_mail *mail,
                              const struct exmdbc_untagged_reply *reply,
                              const struct exmdbc_arg *args)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_fetch_update called (dummy)\n");
    // TODO: Parse Gromox fetch result into internal state
}
