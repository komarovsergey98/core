/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
//#include "imap-arg.h"
//#include "imap-quote.h"
#include "exmdbc-storage.h"
#include "exmdbc-mailbox.h"
#include "exmdbc-attribute.h"

#include <stdio.h>

#define DEPTH_INFINITY (-1)
#define DEPTH_NONE     0

#define ITER_CONTAINER(_iter) \
	container_of(_iter, struct exmdbc_storage_attribute_iter, iter);

enum exmdbc_attribute_command_enum {
	GETMETADATA = 1,
	SETMETADATA = 2
};

struct exmdbc_storage_attribute_iter {
	struct mailbox_attribute_iter iter;
	struct exmdbc_storage_attribute_context *actx;
	struct mailbox_attribute_iter *ictx;
	bool failed:1;
};

static inline struct exmdbc_storage_attribute_context *
exmdbc_storage_attribute_context_create(void)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_context_create called\n");
	pool_t pool = pool_alloconly_create("exmdbc storage attribute context", 256);
	struct exmdbc_storage_attribute_context *actx =
		p_new(pool, struct exmdbc_storage_attribute_context, 1);
	actx->pool = pool;
	return actx;
}

static void
exmdbc_storage_attribute_context_destroy(struct exmdbc_storage_attribute_context **_actx)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_context_destroy called\n");
	struct exmdbc_storage_attribute_context *actx = *_actx;
	*_actx = NULL;
	pool_unref(&actx->pool);
}

static struct exmdbc_storage_attribute_iter *exmdbc_storage_attribute_iter_create()
{
	i_debug("[exmdbc] exmdbc_storage_attribute_iter called\n");
	struct exmdbc_storage_attribute_context *actx =
		exmdbc_storage_attribute_context_create();

	struct exmdbc_storage_attribute_iter *iter =
		p_new(actx->pool, struct exmdbc_storage_attribute_iter, 1);
	iter->actx = actx;
	return iter;
}

static void
exmdbc_storage_attribute_iter_destroy(struct exmdbc_storage_attribute_iter **_iter)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_iter_destroy called\n");
	struct exmdbc_storage_attribute_iter *iter = *_iter;
	exmdbc_storage_attribute_context_destroy(&iter->actx);
	*_iter = NULL;
}

static const char *
exmdbc_storage_attribute_build_cmd(struct exmdbc_mailbox *mbox,
				  enum exmdbc_attribute_command_enum command,
				  int depth,
				  enum mail_attribute_type type_flags,
				  const char *key, const char *value)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_build_cmd called\n");
	const char *mbname = exmdbc_mailbox_get_remote_name(mbox);
	const char *fkey = t_strdup_printf(
		"/%s/%s", type_flags == MAIL_ATTRIBUTE_TYPE_PRIVATE ?
		"private" : "shared", key);
	fkey = t_str_rtrim(fkey, "/");

	string_t *text = t_str_new(64);
	str_append(text, command == GETMETADATA ? "GETMETADATA" : "SETMETADATA");

	if (command == GETMETADATA) {
		if (depth < 0)
			str_append(text, " (DEPTH infinity)");
		else if (depth > 0)
			str_printfa(text, " (DEPTH %d)", depth);
	}
	//TODO:EXMDBC:
	return str_c(text);
}


static int
exmdbc_storage_attribute_cmd(struct mailbox *box,
			    enum exmdbc_attribute_command_enum command,
			    enum mail_attribute_type type_flags,
			    int depth, const char *key, const char *value,
			    struct exmdbc_storage_attribute_context *actx)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_cmd called\n");
	struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(box);
	const char *line = exmdbc_storage_attribute_build_cmd(
		mbox, command, depth, type_flags, key, value);
	return -1;
}

enum handling {
	HANDLE_ERROR 	   = -1, /* the call should fail */
	HANDLE_UNAVAILABLE = -2, /* backend doesn't support METADATA */
	HANDLE_IMAPC 	   =  0, /* execute using backend */
	HANDLE_INDEX 	   =  1, /* execute using local (pvt) index */
};

static enum handling
exmdbc_storage_attribute_handling(struct mailbox *box,
				 enum mail_attribute_type type_flags,
				 const char *key)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_handling called\n");
	/* this prefix has special handling, fall back on index_attribute */
	if (str_begins_with(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT))
		return HANDLE_INDEX;

	//TODO:EXMDBC:

	return HANDLE_IMAPC;
}

int exmdbc_storage_attribute_set(struct mailbox_transaction_context *t,
				enum mail_attribute_type type_flags,
				const char *key,
				const struct mail_attribute_value *value)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_set called\n");
	switch (exmdbc_storage_attribute_handling(t->box, type_flags, key)) {
	case HANDLE_INDEX:
		return index_storage_attribute_set(t, type_flags, key, value);
	case HANDLE_IMAPC:
		break;
	default:
		return -1;
	}

	const char *value_str;
	if (mailbox_attribute_value_to_string(t->box->storage, value, &value_str) < 0)
		return -1;

	return exmdbc_storage_attribute_cmd(t->box, SETMETADATA, type_flags,
					   DEPTH_NONE, key, value_str, NULL);
}

int exmdbc_storage_attribute_get(struct mailbox *box,
				enum mail_attribute_type type_flags,
				const char *key,
				struct mail_attribute_value *value_r)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_get called\n");
	switch (exmdbc_storage_attribute_handling(box, type_flags, key)) {
	case HANDLE_INDEX:
		return index_storage_attribute_get(box, type_flags, key, value_r);
	case HANDLE_IMAPC:
		break;
	default:
		return -1;
	}

	struct exmdbc_storage_attribute_context *actx =
		exmdbc_storage_attribute_context_create();
	int ret = exmdbc_storage_attribute_cmd(box, GETMETADATA, type_flags,
					      DEPTH_NONE, key, NULL, actx);
	value_r->value = ret < 0 ? NULL : t_strdup(actx->value);
	exmdbc_storage_attribute_context_destroy(&actx);
	return ret;
}

struct mailbox_attribute_iter *
exmdbc_storage_attribute_iter_init(struct mailbox *box,
				  enum mail_attribute_type type_flags,
				  const char *prefix)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_iter_init called\n");
	struct exmdbc_storage_attribute_iter *iter =
		exmdbc_storage_attribute_iter_create();

	switch (exmdbc_storage_attribute_handling(box, type_flags, prefix)) {
	case HANDLE_INDEX:
		iter->ictx = index_storage_attribute_iter_init(box, type_flags,
							       prefix);
		break;
	case HANDLE_IMAPC:
		if (exmdbc_storage_attribute_cmd(box, GETMETADATA, type_flags,
					        DEPTH_INFINITY, prefix, NULL,
						iter->actx) < 0) {
			mail_storage_last_error_push(box->storage);
			iter->failed = TRUE;
		}
		break;
	case HANDLE_UNAVAILABLE:
		break;
	default:
		mail_storage_last_error_push(box->storage);
		iter->failed = TRUE;
		break;
	}

	iter->iter.box = box;
	return &iter->iter;
}

const char *
exmdbc_storage_attribute_iter_next(struct mailbox_attribute_iter *_iter)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_iter_next called\n");
	struct exmdbc_storage_attribute_iter *iter = ITER_CONTAINER(_iter);

	if (iter->ictx != NULL)
		return index_storage_attribute_iter_next(iter->ictx);

	if (iter->failed || iter->actx == NULL || iter->actx->keys == NULL)
		return NULL;

	const char *key = *(iter->actx->keys);
	if (key == NULL)
		return NULL;

	iter->actx->keys++;

	/* skip the leading "/private/" or "/shared/" part */
	i_assert(*key == '/');
	key = strchr(++key, '/');
	if (key != NULL)
		key++;

	return key;
}

int exmdbc_storage_attribute_iter_deinit(struct mailbox_attribute_iter *_iter)
{
	i_debug("[exmdbc] exmdbc_storage_attribute_iter_deinit called\n");
	struct exmdbc_storage_attribute_iter *iter = ITER_CONTAINER(_iter);

	int ret;
	if (iter->ictx != NULL)
		ret = index_storage_attribute_iter_deinit(iter->ictx);
	else if (!iter->failed)
		ret = 0;
	else {
		mail_storage_last_error_pop(iter->iter.box->storage);
		ret = -1;
	}

	exmdbc_storage_attribute_iter_destroy(&iter);
	return ret;
}
