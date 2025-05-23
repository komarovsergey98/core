/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "mech.h"
#include "str.h"
#include "strfuncs.h"
#include "passdb.h"

#include <ctype.h>

static struct mech_module_list *mech_modules;

void mech_register_module(const struct mech_module *module)
{
	struct mech_module_list *list;
	i_assert(strcmp(module->mech_name, t_str_ucase(module->mech_name)) == 0);

	list = i_new(struct mech_module_list, 1);
	list->module = *module;

	list->next = mech_modules;
	mech_modules = list;
}

void mech_unregister_module(const struct mech_module *module)
{
	struct mech_module_list **pos, *list;

	for (pos = &mech_modules; *pos != NULL; pos = &(*pos)->next) {
		if (strcmp((*pos)->module.mech_name, module->mech_name) == 0) {
			list = *pos;
			*pos = (*pos)->next;
			i_free(list);
			break;
		}
	}
}

const struct mech_module *mech_module_find(const char *name)
{
	struct mech_module_list *list;
	name = t_str_ucase(name);

	for (list = mech_modules; list != NULL; list = list->next) {
		if (strcmp(list->module.mech_name, name) == 0)
			return &list->module;
	}
	return NULL;
}

void mech_generic_auth_initial(struct auth_request *request,
			       const unsigned char *data, size_t data_size)
{
	if (data == NULL) {
		auth_request_handler_reply_continue(request, uchar_empty_ptr, 0);
	} else {
		/* initial reply given, even if it was 0 bytes */
		request->mech->auth_continue(request, data, data_size);
	}
}

void mech_generic_auth_free(struct auth_request *request)
{
	pool_unref(&request->pool);
}

extern const struct mech_module mech_plain;
extern const struct mech_module mech_login;
extern const struct mech_module mech_apop;
extern const struct mech_module mech_cram_md5;
extern const struct mech_module mech_digest_md5;
extern const struct mech_module mech_external;
extern const struct mech_module mech_otp;
extern const struct mech_module mech_scram_sha1;
extern const struct mech_module mech_scram_sha1_plus;
extern const struct mech_module mech_scram_sha256;
extern const struct mech_module mech_scram_sha256_plus;
extern const struct mech_module mech_anonymous;
#ifdef HAVE_GSSAPI
extern const struct mech_module mech_gssapi;
#endif
#ifdef HAVE_GSSAPI_SPNEGO
extern const struct mech_module mech_gssapi_spnego;
#endif
extern const struct mech_module mech_winbind_ntlm;
extern const struct mech_module mech_winbind_spnego;
extern const struct mech_module mech_oauthbearer;
extern const struct mech_module mech_xoauth2;

static void mech_register_add(struct mechanisms_register *reg,
			      const struct mech_module *mech)
{
	struct mech_module_list *list;
	string_t *handshake;

	list = p_new(reg->pool, struct mech_module_list, 1);
	list->module = *mech;

	if ((mech->flags & MECH_SEC_CHANNEL_BINDING) != 0)
		handshake = reg->handshake_cbind;
	else
		handshake = reg->handshake;

	str_printfa(handshake, "MECH\t%s", mech->mech_name);
	if ((mech->flags & MECH_SEC_PRIVATE) != 0)
		str_append(handshake, "\tprivate");
	if ((mech->flags & MECH_SEC_ANONYMOUS) != 0)
		str_append(handshake, "\tanonymous");
	if ((mech->flags & MECH_SEC_PLAINTEXT) != 0)
		str_append(handshake, "\tplaintext");
	if ((mech->flags & MECH_SEC_DICTIONARY) != 0)
		str_append(handshake, "\tdictionary");
	if ((mech->flags & MECH_SEC_ACTIVE) != 0)
		str_append(handshake, "\tactive");
	if ((mech->flags & MECH_SEC_FORWARD_SECRECY) != 0)
		str_append(handshake, "\tforward-secrecy");
	if ((mech->flags & MECH_SEC_MUTUAL_AUTH) != 0)
		str_append(handshake, "\tmutual-auth");
	if ((mech->flags & MECH_SEC_CHANNEL_BINDING) != 0)
		str_append(handshake, "\tchannel-binding");
	str_append_c(handshake, '\n');

	list->next = reg->modules;
	reg->modules = list;
}

static const char *mech_get_plugin_name(const char *name)
{
	string_t *str = t_str_new(32);

	str_append(str, "mech_");
	for (; *name != '\0'; name++) {
		if (*name == '-')
			str_append_c(str, '_');
		else
			str_append_c(str, i_tolower(*name));
	}
	return str_c(str);
}

struct mechanisms_register *
mech_register_init(const struct auth_settings *set)
{
	struct mechanisms_register *reg;
	const struct mech_module *mech;
	const char *name;
	pool_t pool;

	pool = pool_alloconly_create("mechanisms register", 1024);
	reg = p_new(pool, struct mechanisms_register, 1);
	reg->pool = pool;
	reg->set = set;
	reg->handshake = str_new(pool, 512);
	reg->handshake_cbind = str_new(pool, 256);

	if (!array_is_created(&set->mechanisms) ||
	    array_is_empty(&set->mechanisms))
		i_fatal("No authentication mechanisms configured");

	array_foreach_elem(&set->mechanisms, name) {
		name = t_str_ucase(name);

		if (strcmp(name, "ANONYMOUS") == 0) {
			if (*set->anonymous_username == '\0') {
				i_fatal("ANONYMOUS listed in mechanisms, "
					"but anonymous_username not set");
			}
		}
		mech = mech_module_find(name);
		if (mech == NULL) {
			/* maybe it's a plugin. try to load it. */
			auth_module_load(mech_get_plugin_name(name));
			mech = mech_module_find(name);
		}
		if (mech == NULL)
			i_fatal("Unknown authentication mechanism '%s'", name);
		mech_register_add(reg, mech);
	}
	return reg;
}

void mech_register_deinit(struct mechanisms_register **_reg)
{
	struct mechanisms_register *reg = *_reg;

	*_reg = NULL;
	pool_unref(&reg->pool);
}

const struct mech_module *
mech_register_find(const struct mechanisms_register *reg, const char *name)
{
	const struct mech_module_list *list;
	name = t_str_ucase(name);

	for (list = reg->modules; list != NULL; list = list->next) {
		if (strcmp(list->module.mech_name, name) == 0)
			return &list->module;
	}
	return NULL;
}

void mech_init(const struct auth_settings *set)
{
	mech_register_module(&mech_plain);
	mech_register_module(&mech_login);
	mech_register_module(&mech_apop);
	mech_register_module(&mech_cram_md5);
	mech_register_module(&mech_digest_md5);
	mech_register_module(&mech_external);
	if (set->use_winbind) {
		mech_register_module(&mech_winbind_ntlm);
		mech_register_module(&mech_winbind_spnego);
	} else {
#if defined(HAVE_GSSAPI_SPNEGO) && defined(BUILTIN_GSSAPI)
		mech_register_module(&mech_gssapi_spnego);
#endif
	}
	mech_register_module(&mech_otp);
	mech_register_module(&mech_scram_sha1);
	mech_register_module(&mech_scram_sha1_plus);
	mech_register_module(&mech_scram_sha256);
	mech_register_module(&mech_scram_sha256_plus);
	mech_register_module(&mech_anonymous);
#ifdef BUILTIN_GSSAPI
	mech_register_module(&mech_gssapi);
#endif
	mech_register_module(&mech_oauthbearer);
	mech_register_module(&mech_xoauth2);
	mech_oauth2_initialize();
}

void mech_deinit(const struct auth_settings *set)
{
	mech_unregister_module(&mech_plain);
	mech_unregister_module(&mech_login);
	mech_unregister_module(&mech_apop);
	mech_unregister_module(&mech_cram_md5);
	mech_unregister_module(&mech_digest_md5);
	mech_unregister_module(&mech_external);
	if (set->use_winbind) {
		mech_unregister_module(&mech_winbind_ntlm);
		mech_unregister_module(&mech_winbind_spnego);
	} else {
#if defined(HAVE_GSSAPI_SPNEGO) && defined(BUILTIN_GSSAPI)
		mech_unregister_module(&mech_gssapi_spnego);
#endif
	}
	mech_unregister_module(&mech_otp);
	mech_unregister_module(&mech_scram_sha1);
	mech_unregister_module(&mech_scram_sha1_plus);
	mech_unregister_module(&mech_scram_sha256);
	mech_unregister_module(&mech_scram_sha256_plus);
	mech_unregister_module(&mech_anonymous);
#ifdef BUILTIN_GSSAPI
	mech_unregister_module(&mech_gssapi);
#endif
	mech_unregister_module(&mech_oauthbearer);
	mech_unregister_module(&mech_xoauth2);
}
