#include "lib.h"
#include "str.h"
#include "hex-binary.h"
#include "sha1.h"
#include "istream.h"
#include "index-mail.h"
#include "exmdbc-mail.h"

#include <stdio.h>

#include "exmdbc-storage.h"
#include "exmdbc-mailbox.h"

static bool exmdbc_mail_get_cached_guid(struct mail *_mail);

struct mail *
exmdbc_mail_alloc(struct mailbox_transaction_context *t,
                  enum mail_fetch_field wanted_fields,
                  struct mailbox_header_lookup_ctx *wanted_headers)
{
	fprintf(stdout, "!!! exmdbc_mail_alloc called\n");
	struct exmdbc_mail *mail;
	pool_t pool = pool_alloconly_create("exmdbc_mail", 2048);

	mail = p_new(pool, struct exmdbc_mail, 1);
	index_mail_init(&mail->imail, t, wanted_fields, wanted_headers, pool, NULL);

	return &mail->imail.mail.mail;
}

static bool exmdbc_mail_is_expunged(struct mail *_mail)
{
	fprintf(stdout, "!!! exmdbc_mail_is_expunged called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct exmdbc_msgmap *msgmap;
	uint32_t lseq, rseq;

	if (!mbox->initial_sync_done) {
		return FALSE;
	}

	if (mbox->sync_view != NULL) {
		if (!mail_index_lookup_seq(mbox->sync_view, _mail->uid, &lseq))
			return TRUE;
	}
	//TODO:EXMDBC:
	//msgmap = exmdbc_client_mailbox_get_msgmap(mbox->client_box);
	if (!exmdbc_msgmap_uid_to_rseq(msgmap, _mail->uid, &rseq))
		return TRUE;

	exmdbc_mailbox_noop(mbox);
	if (!mbox->initial_sync_done) {
		return FALSE;
	}

	return !exmdbc_msgmap_uid_to_rseq(msgmap, _mail->uid, &rseq);
}

static int exmdbc_mail_failed(struct mail *mail, const char *field)
{
	fprintf(stdout, "!!! exmdbc_mail_failed called\n");
	struct exmdbc_mail *imail = EXMDBC_MAIL(mail);
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(mail->box);
	bool fix_broken_mail = FALSE;
	//TODO:EXMDBC:
	if (mail->expunged || exmdbc_mail_is_expunged(mail)) {
		mail_set_expunged(mail);
	//} else if (!exmdbc_client_mailbox_is_opened(mbox->client_box)) {
	//	/* we've already logged a disconnection error */
	//	mail_storage_set_internal_error(mail->box->storage);
	} else {
		/* By default we'll assume that this is a critical failure,
		   because we don't want to lose any data. We can be here
		   either because it's a temporary failure on the server or
		   it's a permanent failure. Unfortunately we can't know
		   which case it is, so permanent failures need to be worked
		   around by setting exmdbc_features=fetch-fix-broken-mails.

		   One reason for permanent failures was that earlier Exchange
		   versions failed to return any data for messages in Calendars
		   mailbox. This seems to be fixed in newer versions.
		   */
		fix_broken_mail = imail->fetch_ignore_if_missing;
		mail_set_critical(mail,
			"exmdbc: Remote server didn't send %s%s (FETCH replied: %s)",
			field, fix_broken_mail ? " - treating it as empty" : "",
			imail->last_fetch_reply);
	}
	return fix_broken_mail ? 0 : -1;
}

static int exmdbc_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_received_date called\n");
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;

	if (index_mail_get_received_date(_mail, date_r) == 0)
		return 0;

	if (data->received_date == (time_t)-1) {
		if (exmdbc_mail_fetch(_mail, MAIL_FETCH_RECEIVED_DATE, NULL) < 0)
			return -1;
		if (data->received_date == (time_t)-1) {
			if (exmdbc_mail_failed(_mail, "INTERNALDATE") < 0)
				return -1;
			/* assume that the server never returns INTERNALDATE
			   for this mail (see BODY[] failure handling) */
			data->received_date = 0;
		}
	}
	*date_r = data->received_date;
	return 0;
}

static int exmdbc_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_save_date called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;

	if (data->save_date != 0 && index_mail_get_save_date(_mail, date_r) > 0)
		return 1;

	//TODO:EXMDBC:
	return 1;
}

static int exmdbc_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_physical_size called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;
	struct istream *input;
	uoff_t old_offset;
	int ret;

	if (data->physical_size == UOFF_T_MAX)
		(void)index_mail_get_physical_size(_mail, size_r);
	if (data->physical_size != UOFF_T_MAX) {
		*size_r = data->physical_size;
		return 0;
	}

	//TODO:EXMDBC:
	return 0;
}

static int exmdbc_mail_get_virtual_size(struct mail *_mail, uoff_t *size_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_virtual_size called\n");
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;

	if (exmdbc_mail_get_physical_size(_mail, size_r) < 0)
		return -1;
	data->virtual_size = data->physical_size;
	return 0;
}

static int exmdbc_mail_get_header_stream(struct mail *_mail,
			     struct mailbox_header_lookup_ctx *headers,
			     struct istream **stream_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_header_stream called\n");
	struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);

	//TODO:EXMDBC:
	return -1;
}

static int
exmdbc_mail_get_headers(struct mail *_mail, const char *field,
		       bool decode_to_utf8, const char *const **value_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_headers called\n");
	struct mailbox_header_lookup_ctx *headers;
	const char *header_names[2];
	const unsigned char *data;
	size_t size;
	struct istream *input;
	int ret;

	header_names[0] = field;
	header_names[1] = NULL;
	headers = mailbox_header_lookup_init(_mail->box, header_names);
	ret = mail_get_header_stream(_mail, headers, &input);
	mailbox_header_lookup_unref(&headers);
	if (ret < 0)
		return -1;

	while (i_stream_read_more(input, &data, &size) > 0)
		i_stream_skip(input, size);
	/* the header should cached now. */
	return index_mail_get_headers(_mail, field, decode_to_utf8, value_r);
}

static int
exmdbc_mail_get_first_header(struct mail *_mail, const char *field,
			    bool decode_to_utf8, const char **value_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_first_header called\n");
	const char *const *values;
	int ret;

	ret = exmdbc_mail_get_headers(_mail, field, decode_to_utf8, &values);
	if (ret <= 0)
		return ret;
	*value_r = values[0];
	return 1;
}

static int
exmdbc_mail_get_stream(struct mail *_mail, bool get_body,
		      struct message_size *hdr_size,
		      struct message_size *body_size, struct istream **stream_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_stream called\n");
	struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	enum mail_fetch_field fetch_field;

	if (get_body && !mail->body_fetched &&
	    mail->imail.data.stream != NULL) {
		/* we've fetched the header, but we need the body now too */
		index_mail_close_streams(&mail->imail);
		/* don't re-use any cached header sizes. we may be
		   intentionally downloading the full body because the header
		   wasn't returned correctly (e.g. pop3-migration does this) */
		data->hdr_size_set = FALSE;
	}

	/* See if we can get it from cache. If the wanted_fields/headers are
	   set properly, this is usually already done by prefetching. */
	exmdbc_mail_try_init_stream_from_cache(mail);

	if (data->stream == NULL) {
		if (!data->initialized) {
			/* coming here from mail_set_seq() */
			mail_set_aborted(_mail);
			return -1;
		}
		if (_mail->expunged) {
			/* We already detected that the mail is expunged.
			   Don't spend time trying to FETCH it again. */
			mail_set_expunged(_mail);
			return -1;
		}
		fetch_field = get_body ||
			(data->access_part & READ_BODY) != 0 ?
			MAIL_FETCH_STREAM_BODY : MAIL_FETCH_STREAM_HEADER;
		if (exmdbc_mail_fetch(_mail, fetch_field, NULL) < 0)
			return -1;

		if (data->stream == NULL) {
			if (exmdbc_mail_failed(_mail, "BODY[]") < 0)
				return -1;
			i_assert(data->stream == NULL);

			/* return the broken email as empty */
			mail->body_fetched = TRUE;
			data->stream = i_stream_create_from_data(NULL, 0);
			exmdbc_mail_init_stream(mail);
		}
	}

	return index_mail_init_stream(&mail->imail, hdr_size, body_size,
				      stream_r);
}

bool exmdbc_mail_has_headers_in_cache(struct index_mail *mail,
				     struct mailbox_header_lookup_ctx *headers)
{
	fprintf(stdout, "!!! exmdbc_mail_has_headers_in_cache called\n");
	struct mail *_mail = &mail->mail.mail;
	unsigned int i;

	for (i = 0; i < headers->count; i++) {
		if (mail_cache_field_exists(_mail->transaction->cache_view,
					    _mail->seq, headers->idx[i]) <= 0)
			return FALSE;
	}
	return TRUE;
}

void exmdbc_mail_update_access_parts(struct index_mail *mail)
{
	fprintf(stdout, "!!! exmdbc_mail_update_access_parts called\n");
	struct mail *_mail = &mail->mail.mail;
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct index_mail_data *data = &mail->data;
	struct mailbox_header_lookup_ctx *header_ctx;
	const char *str;
	time_t date;
	uoff_t size;

	//TODO:EXMDBC:
}

static void exmdbc_mail_set_seq(struct mail *_mail, uint32_t seq, bool saving)
{
	fprintf(stdout, "!!! exmdbc_mail_set_seq called\n");
	struct exmdbc_mail *imail = EXMDBC_MAIL(_mail);
	struct index_mail *mail = &imail->imail;
	struct exmdbc_mailbox *mbox = (struct exmdbc_mailbox *)_mail->box;


	//TODO:EXMDBC:
}

static void
exmdbc_mail_add_temp_wanted_fields(struct mail *_mail,
				  enum mail_fetch_field fields,
				  struct mailbox_header_lookup_ctx *headers)
{
	fprintf(stdout, "!!! exmdbc_mail_add_temp_wanted_fields called\n");
	struct index_mail *mail = INDEX_MAIL(_mail);

	index_mail_add_temp_wanted_fields(_mail, fields, headers);
	if (_mail->seq != 0)
		exmdbc_mail_update_access_parts(mail);
}

static void exmdbc_mail_close(struct mail *_mail)
{
	fprintf(stdout, "!!! exmdbc_mail_close called\n");
	struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct exmdbc_mail_cache *cache = &mbox->prev_mail_cache;

	if (mail->fetch_count > 0) {
		exmdbc_mail_fetch_flush(mbox);
		while (mail->fetch_count > 0)
			exmdbc_mailbox_run_nofetch(mbox);
	}

	index_mail_close(_mail);

	mail->fetching_headers = NULL;
	if (mail->body_fetched) {
		exmdbc_mail_cache_free(cache);
		cache->uid = _mail->uid;
		if (mail->fd != -1) {
			cache->fd = mail->fd;
			mail->fd = -1;
		} else {
			cache->buf = mail->body;
			mail->body = NULL;
		}
	}
	i_close_fd(&mail->fd);
	buffer_free(&mail->body);
	mail->header_fetched = FALSE;
	mail->body_fetched = FALSE;

	i_assert(mail->fetch_count == 0);
}

static int exmdbc_mail_get_hdr_hash(struct index_mail *imail)
{
	fprintf(stdout, "!!! exmdbc_mail_get_hdr_hash called\n");
	struct istream *input;
	const unsigned char *data;
	size_t size;
	uoff_t old_offset;
	struct sha1_ctxt sha1_ctx;
	unsigned char sha1_output[SHA1_RESULTLEN];
	const char *sha1_str;

	sha1_init(&sha1_ctx);
	old_offset = imail->data.stream == NULL ? 0 :
		imail->data.stream->v_offset;
	if (mail_get_hdr_stream(&imail->mail.mail, NULL, &input) < 0)
		return -1;
	i_assert(imail->data.stream != NULL);
	while (i_stream_read_more(input, &data, &size) > 0) {
		sha1_loop(&sha1_ctx, data, size);
		i_stream_skip(input, size);
	}
	i_stream_seek(imail->data.stream, old_offset);
	sha1_result(&sha1_ctx, sha1_output);

	sha1_str = binary_to_hex(sha1_output, sizeof(sha1_output));
	imail->data.guid = p_strdup(imail->mail.data_pool, sha1_str);
	return 0;
}

static bool exmdbc_mail_get_cached_guid(struct mail *_mail)
{
	fprintf(stdout, "!!! exmdbc_mail_get_cached_guid called\n");
	struct index_mail *imail = INDEX_MAIL(_mail);
	const enum index_cache_field cache_idx =
		imail->ibox->cache_fields[MAIL_CACHE_GUID].idx;
	string_t *str;

	if (imail->data.guid != NULL) {
		if (mail_cache_field_can_add(_mail->transaction->cache_trans,
					     _mail->seq, cache_idx)) {
			/* GUID was prefetched - add to cache */
			index_mail_cache_add_idx(imail, cache_idx,
				imail->data.guid, strlen(imail->data.guid));
		}
		return TRUE;
	}

	str = str_new(imail->mail.data_pool, 64);
	if (mail_cache_lookup_field(_mail->transaction->cache_view,
				    str, imail->mail.mail.seq, cache_idx) > 0) {
		imail->data.guid = str_c(str);
		return TRUE;
	}
	return FALSE;
}

static int exmdbc_mail_get_guid(struct mail *_mail, const char **value_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_guid called\n");
	struct index_mail *imail = INDEX_MAIL(_mail);
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	const enum index_cache_field cache_idx =
		imail->ibox->cache_fields[MAIL_CACHE_GUID].idx;

	if (exmdbc_mail_get_cached_guid(_mail)) {
		*value_r = imail->data.guid;
		return 0;
	}

	/* GUID not in cache, fetch it */
	if (mbox->guid_fetch_field_name != NULL) {
		if (exmdbc_mail_fetch(_mail, MAIL_FETCH_GUID, NULL) < 0)
			return -1;
		if (imail->data.guid == NULL) {
			(void)exmdbc_mail_failed(_mail, mbox->guid_fetch_field_name);
			return -1;
		}
	} else {
		/* use hash of message headers as the GUID */
		if (exmdbc_mail_get_hdr_hash(imail) < 0)
			return -1;
	}

	index_mail_cache_add_idx(imail, cache_idx,
				 imail->data.guid, strlen(imail->data.guid));
	*value_r = imail->data.guid;
	return 0;
}

static int
exmdbc_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		       const char **value_r)
{
	fprintf(stdout, "!!! exmdbc_mail_get_special called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct index_mail *imail = INDEX_MAIL(_mail);
	uint64_t num;


	//TODO:EXMDBC:
	return -1;
}

static uint64_t exmdbc_mail_get_modseq(struct mail *_mail)
{
	fprintf(stdout, "!!! exmdbc_mail_get_modseq called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);
	struct exmdbc_msgmap *msgmap;
	const uint64_t *modseqs;
	unsigned int count;
	uint32_t rseq;

	if (!exmdbc_mailbox_has_modseqs(mbox))
		return index_mail_get_modseq(_mail);

	//TODO:EXMDBC:
	//msgmap = exmdbc_client_mailbox_get_msgmap(mbox->client_box);
	if (exmdbc_msgmap_uid_to_rseq(msgmap, _mail->uid, &rseq)) {
		modseqs = array_get(&mbox->rseq_modseqs, &count);
		if (rseq <= count)
			return modseqs[rseq-1];
	}
	return 1; /* unknown modseq */
}

int exmdbcc_mail_fetch(struct mail *_mail, enum mail_fetch_field fields,
			 const char *const *headers)
{
	fprintf(stdout, "!!! exmdbcc_mail_fetch called\n");
	return -1;
}

void exmdbc_mailbox_noop(struct exmdbc_mailbox *mbox)
{
	fprintf(stdout, "!!! exmdbc_mailbox_noop called\n");
	struct exmdbc_command *cmd;
	struct exmdbc_simple_context sctx;

	if (mbox->client_box == NULL) {
		/* mailbox opening hasn't finished yet */
		return;
	}

	exmdbc_simple_context_init(&sctx, mbox->storage->client);
	//TODO:EXMDBC:
	// cmd = exmdbc_client_mailbox_cmd(mbox->client_box,
	// 				   exmdbc_simple_callback, &sctx);
	// exmdbc_command_send(cmd, "NOOP");
	// exmdbc_simple_run(&sctx, &cmd);
}

struct mail_vfuncs exmdbc_mail_vfuncs = {
  /* exmdbc_mail_close  */  exmdbc_mail_close,
  /* index_mail_free    */  index_mail_free,
  /* exmdbc_mail_set_seq */  exmdbc_mail_set_seq,
  /* index_mail_set_uid */  index_mail_set_uid,
  /* index_mail_set_uid_cache_updates */ index_mail_set_uid_cache_updates,
  /* exmdbc_mail_prefetch*/  exmdbc_mail_prefetch,
  /* index_mail_precache*/  index_mail_precache,
  /* exmdbc_mail_add_temp_wanted_fields */ exmdbc_mail_add_temp_wanted_fields,
  /* index_mail_get_flags */ index_mail_get_flags,
  /* index_mail_get_keywords */ index_mail_get_keywords,
  /* index_mail_get_keyword_indexes */ index_mail_get_keyword_indexes,
  /* exmdbc_mail_get_modseq */ exmdbc_mail_get_modseq,
  /* index_mail_get_pvt_modseq */ index_mail_get_pvt_modseq,
  /* index_mail_get_parts */ index_mail_get_parts,
  /* index_mail_get_date */ index_mail_get_date,
  /* index_mail_get_received_date */ exmdbc_mail_get_received_date,
  /* exmdbc_mail_get_save_date */ exmdbc_mail_get_save_date,
  /* exmdbc_mail_get_virtual_size */ exmdbc_mail_get_virtual_size,
  /* exmdbc_mail_get_physical_size */ exmdbc_mail_get_physical_size,
  /* exmdbc_mail_get_first_header */ exmdbc_mail_get_first_header,
  /* exmdbc_mail_get_headers */ exmdbc_mail_get_headers,
  /* exmdbc_mail_get_header_stream */ exmdbc_mail_get_header_stream,
  /* exmdbc_mail_get_stream */ exmdbc_mail_get_stream,
  /* index_mail_get_binary_stream */ index_mail_get_binary_stream,
  /* exmdbc_mail_get_special */ exmdbc_mail_get_special,
  /* index_mail_get_backend_mail */ index_mail_get_backend_mail,
  /* index_mail_update_flags */ index_mail_update_flags,
  /* index_mail_update_keywords */ index_mail_update_keywords,
  /* index_mail_update_modseq */ index_mail_update_modseq,
  /* index_mail_update_pvt_modseq */ index_mail_update_pvt_modseq,
  /* NULL */
  /* index_mail_expunge */ index_mail_expunge,
  /* index_mail_set_cache_corrupted */ index_mail_set_cache_corrupted,
  /* index_mail_opened */ index_mail_opened,
};
