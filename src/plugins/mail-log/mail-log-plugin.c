/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "str-sanitize.h"
#include "settings.h"
#include "settings-parser.h"
#include "imap-util.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "notify-plugin.h"
#include "mail-log-plugin.h"


#define MAILBOX_NAME_LOG_LEN 64
#define HEADER_LOG_LEN 80

#define MAIL_LOG_USER_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mail_log_user_module)

/* <settings checks> */
enum mail_log_field {
	MAIL_LOG_FIELD_UID	= 0x01,
	MAIL_LOG_FIELD_BOX	= 0x02,
	MAIL_LOG_FIELD_MSGID	= 0x04,
	MAIL_LOG_FIELD_PSIZE	= 0x08,
	MAIL_LOG_FIELD_VSIZE	= 0x10,
	MAIL_LOG_FIELD_FLAGS	= 0x20,
	MAIL_LOG_FIELD_FROM	= 0x40,
	MAIL_LOG_FIELD_SUBJECT	= 0x80
};

enum mail_log_event {
	MAIL_LOG_EVENT_DELETE		= 0x01,
	MAIL_LOG_EVENT_UNDELETE		= 0x02,
	MAIL_LOG_EVENT_EXPUNGE		= 0x04,
	MAIL_LOG_EVENT_SAVE		= 0x08,
	MAIL_LOG_EVENT_COPY		= 0x10,
	MAIL_LOG_EVENT_MAILBOX_CREATE	= 0x20,
	MAIL_LOG_EVENT_MAILBOX_DELETE	= 0x40,
	MAIL_LOG_EVENT_MAILBOX_RENAME	= 0x80,
	MAIL_LOG_EVENT_FLAG_CHANGE	= 0x100
};

static const char *field_names[] = {
	"uid",
	"box",
	"msgid",
	"size",
	"vsize",
	"flags",
	"from",
	"subject",
	NULL
};

static const char *event_names[] = {
	"delete",
	"undelete",
	"expunge",
	"save",
	"copy",
	"mailbox_create",
	"mailbox_delete",
	"mailbox_rename",
	"flag_change",
	NULL
};

struct mail_log_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) mail_log_fields;
	ARRAY_TYPE(const_string) mail_log_events;
	bool mail_log_cached_only;

	enum mail_log_field parsed_fields;
	enum mail_log_event parsed_events;
};
/* </settings checks> */

struct mail_log_user {
	union mail_user_module_context module_ctx;
	const struct mail_log_settings *set;
};

struct mail_log_message {
	struct mail_log_message *prev, *next;

	enum mail_log_event event;
	bool ignore;
	const char *pretext, *text;
};

struct mail_log_mail_txn_context {
	pool_t pool;
	struct event *event;
	struct mail_log_message *messages, *messages_tail;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_log_settings)
static const struct setting_define mail_log_setting_defines[] = {
	DEF(BOOLLIST, mail_log_fields),
	DEF(BOOLLIST, mail_log_events),
	DEF(BOOL, mail_log_cached_only),

	SETTING_DEFINE_LIST_END
};
static const struct mail_log_settings mail_log_default_settings = {
	.mail_log_fields = ARRAY_INIT,
	.mail_log_events = ARRAY_INIT,
	.mail_log_cached_only = FALSE,
};
static const struct setting_keyvalue mail_log_default_settings_keyvalue[] = {
	{ "mail_log_fields/uid", "yes" },
	{ "mail_log_fields/msgid", "yes" },
	{ "mail_log_fields/size", "yes" },
	{ "mail_log_events/delete", "yes" },
	{ "mail_log_events/undelete", "yes" },
	{ "mail_log_events/expunge", "yes" },
	{ "mail_log_events/save", "yes" },
	{ "mail_log_events/copy", "yes" },
	{ "mail_log_events/mailbox_delete", "yes" },
	{ "mail_log_events/mailbox_rename", "yes" },
	{ NULL, NULL }
};

static bool mail_log_settings_check(void *_set, pool_t pool, const char **error_r);

const struct setting_parser_info mail_log_setting_parser_info = {
	.name = "mail_log",
	.plugin_dependency = "lib20_mail_log_plugin",

	.defines = mail_log_setting_defines,
	.defaults = &mail_log_default_settings,
	.default_settings = mail_log_default_settings_keyvalue,
	.check_func = mail_log_settings_check,

	.struct_size = sizeof(struct mail_log_settings),
	.pool_offset1 = 1 + offsetof(struct mail_log_settings, pool),
};

static MODULE_CONTEXT_DEFINE_INIT(mail_log_user_module,
				  &mail_user_module_register);

/* <settings checks> */
static enum mail_log_field mail_log_field_find(const char *name)
{
	unsigned int i;

	for (i = 0; field_names[i] != NULL; i++) {
		if (strcmp(name, field_names[i]) == 0)
			return 1 << i;
	}
	return 0;
}

static enum mail_log_event mail_log_event_find(const char *name)
{
	unsigned int i;

	if (strcmp(name, "append") == 0) {
		/* v1.x backwards compatibility */
		name = "save";
	}
	for (i = 0; event_names[i] != NULL; i++) {
		if (strcmp(name, event_names[i]) == 0)
			return 1 << i;
	}
	return 0;
}

static int
mail_log_parse_fields(const ARRAY_TYPE(const_string) *arr,
		      enum mail_log_field *fields_r, const char **error_r)
{
	const char *str;
	enum mail_log_field field;

	*fields_r = 0;
	array_foreach_elem(arr, str) {
		field = mail_log_field_find(str);
		if (field == 0) {
			*error_r = t_strdup_printf(
				"Unknown field in mail_log_fields: '%s'", str);
			return -1;
		}
		*fields_r |= field;
	}
	return 0;
}

static int
mail_log_parse_events(const ARRAY_TYPE(const_string) *arr,
		      enum mail_log_event *events_r, const char **error_r)
{
	const char *str;
	enum mail_log_event event;

	*events_r = 0;
	array_foreach_elem(arr, str) {
		event = mail_log_event_find(str);
		if (event == 0) {
			*error_r = t_strdup_printf(
				"Unknown event in mail_log_events: '%s'", str);
			return -1;
		}
		*events_r |= event;
	}
	return 0;
}

static bool mail_log_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				    const char **error_r)
{
	struct mail_log_settings *set = _set;

	if (mail_log_parse_fields(&set->mail_log_fields, &set->parsed_fields,
				  error_r) < 0)
		return FALSE;
	if (mail_log_parse_events(&set->mail_log_events, &set->parsed_events,
				  error_r) < 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */

static void mail_log_user_deinit(struct mail_user *user)
{
	struct mail_log_user *muser = MAIL_LOG_USER_CONTEXT(user);

	settings_free(muser->set);
	muser->module_ctx.super.deinit(user);
}

static void mail_log_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct mail_log_user *muser;
	const char *error;

	muser = p_new(user->pool, struct mail_log_user, 1);
	muser->module_ctx.super = *v;
	user->vlast = &muser->module_ctx.super;
	v->deinit = mail_log_user_deinit;
	MODULE_CONTEXT_SET(user, mail_log_user_module, muser);

	if (settings_get(user->event, &mail_log_setting_parser_info, 0,
			 &muser->set, &error) < 0) {
		user->error = p_strdup(user->pool, error);
		return;
	}
}

static void mail_log_append_mailbox_name(string_t *str, struct mail *mail)
{
	const char *mailbox_str;

	mailbox_str = mailbox_get_vname(mail->box);
	str_printfa(str, "box=%s",
		    str_sanitize(mailbox_str, MAILBOX_NAME_LOG_LEN));
}

static void
mail_log_append_mail_header(string_t *str, struct mail *mail,
			    const char *name, const char *header)
{
	const char *value;

	if (mail_get_first_header_utf8(mail, header, &value) <= 0)
		value = "";
	str_printfa(str, "%s=%s", name, str_sanitize(value, HEADER_LOG_LEN));
}

static void
mail_log_append_uid(struct mail_log_mail_txn_context *ctx,
		    struct mail_log_message *msg, string_t *str, uint32_t uid)
{
	if (uid != 0)
		str_printfa(str, "uid=%u", uid);
	else {
		/* we don't know the uid yet, assign it later */
		str_printfa(str, "uid=");
		msg->pretext = p_strdup(ctx->pool, str_c(str));
		str_truncate(str, 0);
	}
}

static void
mail_log_update_wanted_fields(struct mail *mail, enum mail_log_field fields)
{
	enum mail_fetch_field wanted_fields = 0;
	struct mailbox_header_lookup_ctx *wanted_headers = NULL;
	const char *headers[4];
	unsigned int hdr_idx = 0;

	if ((fields & MAIL_LOG_FIELD_MSGID) != 0)
		headers[hdr_idx++] = "Message-ID";
	if ((fields & MAIL_LOG_FIELD_FROM) != 0)
		headers[hdr_idx++] = "From";
	if ((fields & MAIL_LOG_FIELD_SUBJECT) != 0)
		headers[hdr_idx++] = "Subject";
	if (hdr_idx > 0) {
		i_assert(hdr_idx < N_ELEMENTS(headers));
		headers[hdr_idx] = NULL;
		wanted_headers = mailbox_header_lookup_init(mail->box, headers);
	}

	if ((fields & MAIL_LOG_FIELD_PSIZE) != 0)
		wanted_fields |= MAIL_FETCH_PHYSICAL_SIZE;
	if ((fields & MAIL_LOG_FIELD_VSIZE) != 0)
		wanted_fields |= MAIL_FETCH_VIRTUAL_SIZE;

	mail_add_temp_wanted_fields(mail, wanted_fields, wanted_headers);
	mailbox_header_lookup_unref(&wanted_headers);
}

static void
mail_log_append_mail_message_real(struct mail_log_mail_txn_context *ctx,
				  struct mail *mail, enum mail_log_event event,
				  const char *desc)
{
	struct mail_log_user *muser =
		MAIL_LOG_USER_CONTEXT(mail->box->storage->user);
	struct mail_log_message *msg;
	string_t *text;
	uoff_t size;

	msg = p_new(ctx->pool, struct mail_log_message, 1);

	/* avoid parsing through the message multiple times */
	mail_log_update_wanted_fields(mail, muser->set->parsed_fields);

	text = t_str_new(128);
	str_append(text, desc);
	str_append(text, ": ");
	if ((muser->set->parsed_fields & MAIL_LOG_FIELD_BOX) != 0) {
		mail_log_append_mailbox_name(text, mail);
		str_append(text, ", ");
	}
	if ((muser->set->parsed_fields & MAIL_LOG_FIELD_UID) != 0) {
		if (event != MAIL_LOG_EVENT_SAVE &&
		    event != MAIL_LOG_EVENT_COPY)
			mail_log_append_uid(ctx, msg, text, mail->uid);
		else {
			/* with mbox mail->uid contains the uid, but handle
			   this consistently with all mailbox formats */
			mail_log_append_uid(ctx, msg, text, 0);
		}
		/* make sure UID is assigned to this mail */
		mail->transaction->flags |= MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS;
		str_append(text, ", ");
	}
	if ((muser->set->parsed_fields & MAIL_LOG_FIELD_MSGID) != 0) {
		mail_log_append_mail_header(text, mail, "msgid", "Message-ID");
		str_append(text, ", ");
	}
	if ((muser->set->parsed_fields & MAIL_LOG_FIELD_PSIZE) != 0) {
		if (mail_get_physical_size(mail, &size) == 0)
			str_printfa(text, "size=%"PRIuUOFF_T, size);
		else
			str_printfa(text, "size=error");
		str_append(text, ", ");
	}
	if ((muser->set->parsed_fields & MAIL_LOG_FIELD_VSIZE) != 0) {
		if (mail_get_virtual_size(mail, &size) == 0)
			str_printfa(text, "vsize=%"PRIuUOFF_T, size);
		else
			str_printfa(text, "vsize=error");
		str_append(text, ", ");
	}
	if ((muser->set->parsed_fields & MAIL_LOG_FIELD_FROM) != 0) {
		mail_log_append_mail_header(text, mail, "from", "From");
		str_append(text, ", ");
	}
	if ((muser->set->parsed_fields & MAIL_LOG_FIELD_SUBJECT) != 0) {
		mail_log_append_mail_header(text, mail, "subject", "Subject");
		str_append(text, ", ");
	}
	if ((muser->set->parsed_fields & MAIL_LOG_FIELD_FLAGS) != 0) {
		str_printfa(text, "flags=(");
		imap_write_flags(text, mail_get_flags(mail),
				 mail_get_keywords(mail));
		str_append(text, "), ");
	}
	str_truncate(text, str_len(text)-2);

	msg->event = event;
	msg->text = p_strdup(ctx->pool, str_c(text));
	DLLIST2_APPEND(&ctx->messages, &ctx->messages_tail, msg);
}

static void mail_log_add_dummy_msg(struct mail_log_mail_txn_context *ctx,
				   enum mail_log_event event)
{
	struct mail_log_message *msg;

	msg = p_new(ctx->pool, struct mail_log_message, 1);
	msg->event = event;
	msg->ignore = TRUE;
	DLLIST2_APPEND(&ctx->messages, &ctx->messages_tail, msg);
}

static void
mail_log_append_mail_message(struct mail_log_mail_txn_context *ctx,
			     struct mail *mail, enum mail_log_event event,
			     const char *desc)
{
	struct mail_log_user *muser =
		MAIL_LOG_USER_CONTEXT(mail->box->storage->user);

	if ((muser->set->parsed_events & event) == 0) {
		if (event == MAIL_LOG_EVENT_SAVE ||
		    event == MAIL_LOG_EVENT_COPY)
			mail_log_add_dummy_msg(ctx, event);
		return;
	}

	T_BEGIN {
		enum mail_lookup_abort orig_lookup_abort = mail->lookup_abort;

		if (event != MAIL_LOG_EVENT_SAVE &&
		    muser->set->mail_log_cached_only)
			mail->lookup_abort = MAIL_LOOKUP_ABORT_NOT_IN_CACHE;
		mail_log_append_mail_message_real(ctx, mail, event, desc);
		mail->lookup_abort = orig_lookup_abort;
	} T_END;
}

static void *
mail_log_mail_transaction_begin(struct mailbox_transaction_context *t ATTR_UNUSED)
{
	pool_t pool;
	struct mail_log_mail_txn_context *ctx;

	pool = pool_alloconly_create("mail-log", 2048);
	ctx = p_new(pool, struct mail_log_mail_txn_context, 1);
	ctx->pool = pool;
	ctx->event = event_create(t->box->event);
	return ctx;
}

static void mail_log_mail_save(void *txn, struct mail *mail)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;

	mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_SAVE, "save");
}

static void mail_log_mail_copy(void *txn, struct mail *src, struct mail *dst)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;
	struct mail_private *src_pmail = (struct mail_private *)src;
	struct mailbox *src_box = src->box;
	const char *desc;

	if (src_pmail->vmail != NULL) {
		/* copying a mail from virtual storage. src points to the
		   backend mail, but we want to log the virtual mailbox name. */
		src_box = src_pmail->vmail->box;
	}
	desc = t_strdup_printf("copy from %s",
			       str_sanitize(mailbox_get_vname(src_box),
					    MAILBOX_NAME_LOG_LEN));
	mail_log_append_mail_message(ctx, dst,
				     MAIL_LOG_EVENT_COPY, desc);
}

static void mail_log_mail_expunge(void *txn, struct mail *mail)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;
	struct mail_private *p = (struct mail_private*)mail;

	mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_EXPUNGE,
				     p->autoexpunged ? "autoexpunge" : "expunge");
}

static void mail_log_mail_update_flags(void *txn, struct mail *mail,
				       enum mail_flags old_flags)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;
	enum mail_flags new_flags = mail_get_flags(mail);

	if (((old_flags ^ new_flags) & MAIL_DELETED) == 0) {
		mail_log_append_mail_message(ctx, mail,
					     MAIL_LOG_EVENT_FLAG_CHANGE,
					     "flag_change");
	} else if ((old_flags & MAIL_DELETED) == 0) {
		mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_DELETE,
					     "delete");
	} else {
		mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_UNDELETE,
					     "undelete");
	}
}

static void
mail_log_mail_update_keywords(void *txn, struct mail *mail,
			      const char *const *old_keywords ATTR_UNUSED)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;

	mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_FLAG_CHANGE,
				     "flag_change");
}

static void mail_log_save(const struct mail_log_message *msg, uint32_t uid,
			  struct event *event)
{
	if (msg->ignore) {
		/* not logging this save/copy */
	} else if (msg->pretext == NULL)
		e_info(event, "%s", msg->text);
	else if (uid != 0)
		e_info(event, "%s%u%s", msg->pretext, uid, msg->text);
	else
		e_info(event, "%serror%s", msg->pretext, msg->text);
}

static void
mail_log_mail_transaction_commit(void *txn,
				 struct mail_transaction_commit_changes *changes)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;
	struct mail_log_message *msg;
	struct seq_range_iter iter;
	unsigned int n = 0;
	uint32_t uid;

	seq_range_array_iter_init(&iter, &changes->saved_uids);
	for (msg = ctx->messages; msg != NULL; msg = msg->next) {
		if (msg->event == MAIL_LOG_EVENT_SAVE ||
		    msg->event == MAIL_LOG_EVENT_COPY) {
			if (!seq_range_array_iter_nth(&iter, n++, &uid))
				uid = 0;
			mail_log_save(msg, uid, ctx->event);
		} else {
			i_assert(msg->pretext == NULL);
			e_info(ctx->event, "%s", msg->text);
		}
	}
	i_assert(!seq_range_array_iter_nth(&iter, n, &uid));

	event_unref(&ctx->event);
	pool_unref(&ctx->pool);
}

static void mail_log_mail_transaction_rollback(void *txn)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;

	event_unref(&ctx->event);
	pool_unref(&ctx->pool);
}

static void
mail_log_mailbox_create(struct mailbox *box)
{
	struct mail_log_user *muser = MAIL_LOG_USER_CONTEXT(box->storage->user);

	if ((muser->set->parsed_events & MAIL_LOG_EVENT_MAILBOX_CREATE) == 0)
		return;

	e_info(box->event, "Mailbox created");
}

static void
mail_log_mailbox_delete_commit(void *txn ATTR_UNUSED, struct mailbox *box)
{
	struct mail_log_user *muser = MAIL_LOG_USER_CONTEXT(box->storage->user);

	if ((muser->set->parsed_events & MAIL_LOG_EVENT_MAILBOX_DELETE) == 0)
		return;

	e_info(box->event, "Mailbox deleted");
}

static void
mail_log_mailbox_rename(struct mailbox *src, struct mailbox *dest)
{
	struct mail_log_user *muser = MAIL_LOG_USER_CONTEXT(src->storage->user);

	if ((muser->set->parsed_events & MAIL_LOG_EVENT_MAILBOX_RENAME) == 0)
		return;

	e_info(src->event, "Mailbox renamed: %s -> %s",
	       str_sanitize(mailbox_get_vname(src), MAILBOX_NAME_LOG_LEN),
	       str_sanitize(mailbox_get_vname(dest), MAILBOX_NAME_LOG_LEN));
}

static const struct notify_vfuncs mail_log_vfuncs = {
	.mail_transaction_begin = mail_log_mail_transaction_begin,
	.mail_save = mail_log_mail_save,
	.mail_copy = mail_log_mail_copy,
	.mail_expunge = mail_log_mail_expunge,
	.mail_update_flags = mail_log_mail_update_flags,
	.mail_update_keywords = mail_log_mail_update_keywords,
	.mail_transaction_commit = mail_log_mail_transaction_commit,
	.mail_transaction_rollback = mail_log_mail_transaction_rollback,
	.mailbox_create = mail_log_mailbox_create,
	.mailbox_delete_commit = mail_log_mailbox_delete_commit,
	.mailbox_rename = mail_log_mailbox_rename
};

static struct notify_context *mail_log_ctx;

static struct mail_storage_hooks mail_log_mail_storage_hooks = {
	.mail_user_created = mail_log_mail_user_created
};

void mail_log_plugin_init(struct module *module)
{
	mail_log_ctx = notify_register(&mail_log_vfuncs);
	mail_storage_hooks_add(module, &mail_log_mail_storage_hooks);
}

void mail_log_plugin_deinit(void)
{
	mail_storage_hooks_remove(&mail_log_mail_storage_hooks);
	notify_unregister(&mail_log_ctx);
}

const char *mail_log_plugin_dependencies[] = { "notify", NULL };
