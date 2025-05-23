/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-temp.h"
#include "iostream-ssl.h"
#include "settings.h"
#include "master-service.h"
#include "program-client.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"
#include "smtp-submit.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <signal.h>

#define DEFAULT_SUBMISSION_PORT 25

static struct event_category event_category_smtp_submit = {
	.name = "smtp-submit"
};

struct smtp_submit_session {
	pool_t pool;
	struct smtp_submit_settings set;
	struct event *event;
};

struct smtp_submit {
	pool_t pool;

	struct smtp_submit_session *session;
	struct event *event;

	struct ostream *output;
	struct istream *input;

	struct smtp_address *mail_from;
	ARRAY_TYPE(smtp_address) rcpt_to;

	struct timeout *to_error;
	int status;
	const char *error;

	struct program_client *prg_client;
	struct smtp_client *smtp_client;
	struct smtp_client_transaction *smtp_trans;

	smtp_submit_callback_t *callback;
	void *context;

	bool simple:1;
};

struct smtp_submit_session *
smtp_submit_session_init(const struct smtp_submit_input *input,
			 const struct smtp_submit_settings *set)
{
	struct smtp_submit_session *session;
	pool_t pool;

	pool = pool_alloconly_create("smtp submit session", 512);
	session = p_new(pool, struct smtp_submit_session, 1);
	session->pool = pool;

	session->set = *set;
	session->set.hostname =
		p_strdup_empty(pool, set->hostname);
	session->set.submission_host =
		p_strdup_empty(pool, set->submission_host);
	session->set.sendmail_path =
		p_strdup_empty(pool, set->sendmail_path);
	session->set.submission_ssl =
		p_strdup_empty(pool, set->submission_ssl);

	session->event = event_create(input->event_parent);
	event_set_forced_debug(session->event, set->mail_debug);
	event_add_category(session->event, &event_category_smtp_submit);

	return session;
}

void smtp_submit_session_deinit(struct smtp_submit_session **_session)
{
	struct smtp_submit_session *session = *_session;

	*_session = NULL;

	event_unref(&session->event);
	pool_unref(&session->pool);
}

struct smtp_submit *
smtp_submit_init(struct smtp_submit_session *session,
		 const struct smtp_address *mail_from)
{
	struct smtp_submit *subm;
	pool_t pool;

	pool = pool_alloconly_create("smtp submit", 1024);
	subm = p_new(pool, struct smtp_submit, 1);
	subm->session = session;
	subm->pool = pool;

	subm->mail_from = smtp_address_clone(pool, mail_from);;
	p_array_init(&subm->rcpt_to, pool, 2);

	subm->event = event_create(session->event);
	event_add_str(subm->event, "mail_from",
		      smtp_address_encode(subm->mail_from));

	return subm;
}

struct smtp_submit *
smtp_submit_init_simple(const struct smtp_submit_input *input,
			const struct smtp_submit_settings *set,
			const struct smtp_address *mail_from)
{
	struct smtp_submit_session *session;
	struct smtp_submit *subm;

	session = smtp_submit_session_init(input, set);
	subm = smtp_submit_init(session, mail_from);
	subm->simple = TRUE;
	return subm;
}

void smtp_submit_deinit(struct smtp_submit **_subm)
{
	struct smtp_submit *subm = *_subm;

	*_subm = NULL;

	if (subm->output != NULL)
		o_stream_destroy(&subm->output);
	if (subm->input != NULL)
		i_stream_destroy(&subm->input);

	if (subm->prg_client != NULL)
		program_client_destroy(&subm->prg_client);
	if (subm->smtp_trans != NULL)
		smtp_client_transaction_destroy(&subm->smtp_trans);
	if (subm->smtp_client != NULL)
		smtp_client_deinit(&subm->smtp_client);

	timeout_remove(&subm->to_error);

	if (subm->simple)
		 smtp_submit_session_deinit(&subm->session);
	event_unref(&subm->event);
	pool_unref(&subm->pool);
}

void smtp_submit_add_rcpt(struct smtp_submit *subm,
			  const struct smtp_address *rcpt_to)
{
	struct smtp_address *rcpt;

	i_assert(subm->output == NULL);
	i_assert(!smtp_address_isnull(rcpt_to));

	rcpt = smtp_address_clone(subm->pool, rcpt_to);
	array_push_back(&subm->rcpt_to, &rcpt);
}

struct ostream *smtp_submit_send(struct smtp_submit *subm)
{
	i_assert(subm->output == NULL);
	i_assert(array_count(&subm->rcpt_to) > 0);

	event_add_int(subm->event, "recipients", array_count(&subm->rcpt_to));

	subm->output = iostream_temp_create
		(t_strconcat("/tmp/dovecot.",
			master_service_get_name(master_service), NULL), 0);
	o_stream_set_no_error_handling(subm->output, TRUE);
	return subm->output;
}

static void
smtp_submit_callback(struct smtp_submit *subm, int status,
		     const char *error)
{
	struct smtp_submit_result result;
	smtp_submit_callback_t *callback;

	timeout_remove(&subm->to_error);

	struct event_passthrough *e =
		event_create_passthrough(subm->event)->
		set_name("smtp_submit_finished");
	if (status > 0)
		e_debug(e->event(), "Sent message successfully");
	else {
		e->add_str("error", error);
		e_debug(e->event(), "Failed to send message: %s", error);
	}

	i_zero(&result);
	result.status = status;
	result.error = error;

	callback = subm->callback;
	subm->callback = NULL;
	callback(&result, subm->context);
}

static void
smtp_submit_delayed_error_callback(struct smtp_submit *subm)
{
	smtp_submit_callback(subm, -1, subm->error);
}

static void
smtp_submit_delayed_error(struct smtp_submit *subm,
			  const char *error)
{
	subm->status = -1;
	subm->error = p_strdup(subm->pool, error);
	subm->to_error = timeout_add_short(0,
		smtp_submit_delayed_error_callback, subm);
}

static void
smtp_submit_error(struct smtp_submit *subm,
		  int status, const char *error)
{
	const struct smtp_submit_settings *set = &subm->session->set;
	i_assert(status <= 0);
	if (subm->error != NULL)
		return;

	subm->status = status;
	subm->error = p_strdup_printf(subm->pool,
		"smtp(%s): %s",
		set->submission_host, error);
}

static void
smtp_submit_success(struct smtp_submit *subm)
{
	if (subm->error != NULL)
		return;
	subm->status = 1;
}

static void
smtp_submit_send_host_finished(struct smtp_submit *subm)
{
	i_assert(subm->status > 0 || subm->error != NULL);
	smtp_submit_callback(subm, subm->status, subm->error);
	subm->smtp_trans = NULL;
}

static bool
reply_is_temp_fail(const struct smtp_reply *reply)
{
	return (smtp_reply_is_temp_fail(reply) ||
		!smtp_reply_is_remote(reply));
}

static void
rcpt_to_callback(const struct smtp_reply *reply,
		 struct smtp_submit *subm)
{
	if (!smtp_reply_is_success(reply)) {
		smtp_submit_error(subm,
			(reply_is_temp_fail(reply) ? -1 : 0),
			t_strdup_printf("RCPT TO failed: %s",
				smtp_reply_log(reply)));
	}
}

static void
data_callback(const struct smtp_reply *reply,
	      struct smtp_submit *subm)
{
	if (!smtp_reply_is_success(reply)) {
		smtp_submit_error(subm,
			(reply_is_temp_fail(reply) ? -1 : 0),
			t_strdup_printf("DATA failed: %s",
				smtp_reply_log(reply)));
		return;
	}

	smtp_submit_success(subm);
}

static void
data_dummy_callback(const struct smtp_reply *reply ATTR_UNUSED,
		    struct smtp_submit *subm ATTR_UNUSED)
{
	/* nothing */
}

static void
smtp_submit_send_host(struct smtp_submit *subm)
{
	const struct smtp_submit_settings *set = &subm->session->set;
	struct smtp_client_settings smtp_set;
	struct smtp_client *smtp_client;
	struct smtp_client_connection *smtp_conn;
	struct smtp_client_transaction *smtp_trans;
	enum smtp_client_connection_ssl_mode ssl_mode;
	struct smtp_address *rcpt;
	const char *host;
	in_port_t port;

	if (net_str2hostport(set->submission_host,
			     DEFAULT_SUBMISSION_PORT, &host, &port) < 0) {
		smtp_submit_delayed_error(subm, t_strdup_printf(
			"Invalid submission_host: %s", host));
		return;
	}

	i_zero(&smtp_set);
	smtp_set.my_hostname = set->hostname;
	smtp_set.connect_timeout_msecs = set->submission_timeout*1000;
	smtp_set.command_timeout_msecs = set->submission_timeout*1000;
	smtp_set.debug = set->mail_debug;
	smtp_set.event_parent = subm->event;

	ssl_mode = SMTP_CLIENT_SSL_MODE_NONE;
	if (set->submission_ssl != NULL) {
		if (strcasecmp(set->submission_ssl, "smtps") == 0 ||
			strcasecmp(set->submission_ssl, "submissions") == 0)
			ssl_mode = SMTP_CLIENT_SSL_MODE_IMMEDIATE;
		else if (strcasecmp(set->submission_ssl, "starttls") == 0)
			ssl_mode = SMTP_CLIENT_SSL_MODE_STARTTLS;
	}

	smtp_client = smtp_client_init(&smtp_set);
	smtp_conn = smtp_client_connection_create(smtp_client,
		  SMTP_PROTOCOL_SMTP, host, port, ssl_mode, NULL);

	smtp_trans = smtp_client_transaction_create(smtp_conn,
		subm->mail_from, NULL, 0, smtp_submit_send_host_finished, subm);
	smtp_client_connection_unref(&smtp_conn);

	array_foreach_elem(&subm->rcpt_to, rcpt) {
		smtp_client_transaction_add_rcpt(smtp_trans,
			rcpt, NULL, rcpt_to_callback, data_dummy_callback, subm);
	}

	subm->smtp_client = smtp_client;
	subm->smtp_trans = smtp_trans;

	smtp_client_transaction_send
		(smtp_trans, subm->input, data_callback, subm);
	i_stream_unref(&subm->input);
}

static void
smtp_submit_sendmail_callback(enum program_client_exit_status status,
			      struct smtp_submit *subm)
{
	if (status == PROGRAM_CLIENT_EXIT_STATUS_INTERNAL_FAILURE) {
		smtp_submit_callback(subm, -1,
			"Failed to execute sendmail");
		return;
	}
	if (status == PROGRAM_CLIENT_EXIT_STATUS_FAILURE) {
		smtp_submit_callback(subm, -1,
			"Sendmail program returned error");
		return;
	}

	smtp_submit_callback(subm, 1, NULL);
}

static void
smtp_submit_send_sendmail(struct smtp_submit *subm)
{
	const struct smtp_submit_settings *set = &subm->session->set;
	const char *const *sendmail_args, *sendmail_bin, *str;
	ARRAY_TYPE(const_string) args;
	struct smtp_address *rcpt;
	unsigned int i;
	struct program_client_parameters pc_params;
	struct program_client *pc;

	sendmail_args = t_strsplit(set->sendmail_path, " ");
	t_array_init(&args, 16);
	i_assert(sendmail_args[0] != NULL);
	sendmail_bin = sendmail_args[0];
	for (i = 1; sendmail_args[i] != NULL; i++)
		array_push_back(&args, &sendmail_args[i]);

	str = "-i"; array_push_back(&args, &str); /* ignore dots */
	str = "-f"; array_push_back(&args, &str);
	str = !smtp_address_isnull(subm->mail_from) ?
		smtp_address_encode(subm->mail_from) : "<>";
	array_push_back(&args, &str);

	str = "--"; array_push_back(&args, &str);
	array_foreach_elem(&subm->rcpt_to, rcpt) {
		const char *rcpt_encoded = smtp_address_encode(rcpt);
		array_push_back(&args, &rcpt_encoded);
	}
	array_append_zero(&args);

	i_zero(&pc_params);
	pc_params.client_connect_timeout_msecs = set->submission_timeout * 1000;
	pc_params.input_idle_timeout_msecs = set->submission_timeout * 1000;

	pc = program_client_local_create(subm->event, sendmail_bin,
					 array_front(&args), &pc_params);

	program_client_set_input(pc, subm->input);
	i_stream_unref(&subm->input);

	subm->prg_client = pc;

	program_client_run_async(pc, smtp_submit_sendmail_callback, subm);
}

struct smtp_submit_run_context {
	int status;
	char *error;
};

static void
smtp_submit_run_callback(const struct smtp_submit_result *result,
			 struct smtp_submit_run_context *rctx)
{
	rctx->error = i_strdup(result->error);
	rctx->status = result->status;
	io_loop_stop(current_ioloop);
}

int smtp_submit_run(struct smtp_submit *subm,
		    const char **error_r)
{
	struct smtp_submit_run_context rctx;
	struct ioloop *ioloop;

	ioloop = io_loop_create();
	io_loop_set_running(ioloop);

	i_zero(&rctx);
	smtp_submit_run_async(subm,
		smtp_submit_run_callback, &rctx);

	if (io_loop_is_running(ioloop))
		io_loop_run(ioloop);

	io_loop_destroy(&ioloop);

	if (rctx.error == NULL)
		*error_r = NULL;
	else {
		*error_r = t_strdup(rctx.error);
		i_free(rctx.error);
	}

	return rctx.status;
}

#undef smtp_submit_run_async
void smtp_submit_run_async(struct smtp_submit *subm,
			   smtp_submit_callback_t *callback, void *context)
{
	const struct smtp_submit_settings *set = &subm->session->set;
	uoff_t data_size;

	subm->callback = callback;
	subm->context = context;

	/* the mail has been written to a file. now actually send it. */
	subm->input = iostream_temp_finish
		(&subm->output, IO_BLOCK_SIZE);

	if (i_stream_get_size(subm->input, TRUE, &data_size) > 0)
		event_add_int(subm->event, "data_size", data_size);

	struct event_passthrough *e =
		event_create_passthrough(subm->event)->
		set_name("smtp_submit_started");
	e_debug(e->event(), "Started sending message");

	if (set->submission_host != NULL) {
		smtp_submit_send_host(subm);
	} else {
		smtp_submit_send_sendmail(subm);
	}
}
