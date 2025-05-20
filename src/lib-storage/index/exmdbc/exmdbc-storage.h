#ifndef EXMDBC_STORAGE_H
#define EXMDBC_STORAGE_H

#include "index-storage.h"

#define EXMDBC_STORAGE_NAME "exmdbc"

#define EXMDBC_STORAGE(s)	container_of(s, struct exmdbc_storage, storage)
#define EXMDBC_MAILBOX(s)	container_of(s, struct exmdbc_mailbox, box)


//TODO:EXMDBC:remove this

enum exmdbc_command_state {
	EXMDBC_COMMAND_STATE_OK = 0,
	EXMDBC_COMMAND_STATE_NO,
	EXMDBC_COMMAND_STATE_BAD,
	/* Authentication to EXMDB server failed (NO or BAD) */
	EXMDBC_COMMAND_STATE_AUTH_FAILED,
	/* Client was unexpectedly disconnected. */
	EXMDBC_COMMAND_STATE_DISCONNECTED
};
enum exmdbc_arg_type {
	EXMDB_ARG_NIL = 0,
	EXMDB_ARG_ATOM,
	EXMDB_ARG_STRING,
	EXMDB_ARG_LIST,

	/* literals are returned as EXMDB_ARG_STRING by default */
	EXMDB_ARG_LITERAL,
	EXMDB_ARG_LITERAL_SIZE,
	EXMDB_ARG_LITERAL_SIZE_NONSYNC,

	EXMDB_ARG_EOL /* end of argument list */
};

struct exmdbc_command_reply {
	enum exmdbc_command_state state;
	/* "[RESP TEXT]" produces key=RESP, value=TEXT.
	   "[RESP]" produces key=RESP, value=NULL
	   otherwise both are NULL */
	const char *resp_text_key, *resp_text_value;
	/* The full tagged reply, including [RESP TEXT]. */
	const char *text_full;
	/* Tagged reply text without [RESP TEXT] */
	const char *text_without_resp;
};

struct exmdbc_arg_file {
	/* file descriptor containing the value */
	int fd;

	/* parent_arg.list[list_idx] points to the EXMDB_ARG_LITERAL_SIZE
	   argument */
	const struct exmdbc_arg *parent_arg;
	unsigned int list_idx;
};

struct exmdbc_untagged_reply {
	/* name of the untagged reply, e.g. EXISTS */
	const char *name;
	/* number at the beginning of the reply, or 0 if there wasn't any.
	   Set for EXISTS, EXPUNGE, etc. */
	uint32_t num;
	/* the rest of the reply can be read from these args. */
	const struct imap_arg *args;
	/* arguments whose contents are stored into files. only
	   "FETCH (BODY[" arguments can be here. */
	const struct exmdbc_arg_file *file_args;
	unsigned int file_args_count;

	/* "* OK [RESP TEXT]" produces key=RESP, value=TEXT.
	   "* OK [RESP]" produces key=RESP, value=NULL
	   otherwise both are NULL */
	const char *resp_text_key, *resp_text_value;

	/* If this reply occurred while a mailbox was selected, this contains
	   the mailbox's untagged_context. */
	void *untagged_box_context;
};


struct exmdbc_mailbox;

typedef void exmdbc_storage_callback_t(const struct imapc_untagged_reply *reply,
					  struct exmdbc_storage_client *client);
typedef void exmdbc_mailbox_callback_t(const struct imapc_untagged_reply *reply,
					  struct exmdbc_mailbox *mbox);

struct exmdbc_storage_event_callback {
	char *name;
	exmdbc_storage_callback_t *callback;
};

struct exmdbc_mailbox_event_callback {
	const char *name;
	exmdbc_mailbox_callback_t *callback;
};

#define EXMDBC_HAS_FEATURE(mstorage, feature) \
(((mstorage)->set->parsed_features & feature) != 0)
#define EXMDBC_BOX_HAS_FEATURE(mbox, feature) \
(((mbox)->storage->set->parsed_features & feature) != 0)


struct exmdbc_namespace {
	const char *prefix;
	char separator;
	enum mail_namespace_type type;
};

struct exmdbc_storage_attribute_context {
	pool_t pool;
	const char *const *keys;
	const char *value;
	const char *error;
	bool iterating:1;
};

struct exmdbc_storage_client {
	int refcount;

	/* either one of these may not be available: */
	struct exmdbc_storage *_storage;
	struct exmdbc_mailbox_list *_list;

	struct exmdb_client *client;

	/* EXMDBC_COMMAND_STATE_OK if no auth failure (yet), otherwise result to
	   the LOGIN/AUTHENTICATE command. */
	enum exmdbc_command_state auth_failed_state;
	char *auth_failed_reason;

	/* Authentication reply was received (success or failure) */
	bool auth_returned:1;
	bool destroying:1;
};

struct exmdbc_storage {
	struct mail_storage storage;

	struct ioloop *root_ioloop;
	struct exmdbc_storage_client *client;
	const char *mailbox_dir;

	struct exmdbc_mailbox *cur_status_box;
	struct mailbox_status *cur_status;
	struct exmdbc_storage_attribute_context *cur_attribute_context;
	unsigned int reopen_count;

	ARRAY(struct exmdbc_namespace) remote_namespaces;

	bool namespaces_requested:1;
};

struct exmdbc_mail_cache {
	uint32_t uid;

	/* either fd != -1 or buf != NULL */
	int fd;
	buffer_t *buf;
};

struct exmdbc_mailbox {
	struct mailbox box;
	struct exmdbc_storage *storage;
	struct exmdbc_client_mailbox *client_box;


	struct mail_index_transaction *delayed_sync_trans;
	struct mail_index_view *sync_view, *delayed_sync_view;
	struct mail_cache_view *delayed_sync_cache_view;
	struct mail_cache_transaction_ctx *delayed_sync_cache_trans;
	struct timeout *to_idle_check, *to_idle_delay;

	ARRAY(struct exmdbc_fetch_request *) fetch_requests;
	ARRAY(struct exmdbc_untagged_fetch_ctx *) untagged_fetch_contexts;
	/* if non-empty, contains the latest FETCH command we're going to be
	   sending soon (but still waiting to see if we can increase its
	   UID range) */
	string_t *pending_fetch_cmd;
	/* if non-empty, contains the latest COPY command we're going to be
	   sending soon. */
	string_t *pending_copy_cmd;
	char *copy_dest_box;
	struct exmdbc_fetch_request *pending_fetch_request;
	struct exmdbc_copy_request *pending_copy_request;
	struct timeout *to_pending_fetch_send;

	ARRAY(struct exmdbc_mailbox_event_callback) untagged_callbacks;
	ARRAY(struct exmdbc_mailbox_event_callback) resp_text_callbacks;

	enum mail_flags permanent_flags;
	uint32_t highest_nonrecent_uid;

	ARRAY(uint64_t) rseq_modseqs;
	ARRAY_TYPE(seq_range) delayed_expunged_uids;
	ARRAY_TYPE(seq_range) copy_rollback_expunge_uids;
	uint32_t sync_uid_validity;
	uint32_t sync_uid_next;
	uint64_t sync_highestmodseq;
	uint32_t sync_fetch_first_uid;
	uint32_t sync_next_lseq;
	uint32_t sync_next_rseq;
	uint32_t exists_count;
	uint32_t min_append_uid;
	char *sync_gmail_pop3_search_tag;

	/* keep the previous fetched message body cached,
	   mainly for partial IMAP fetches */
	struct exmdbc_mail_cache prev_mail_cache;

	uint32_t prev_skipped_rseq, prev_skipped_uid;
	struct imapc_sync_context *sync_ctx;

	const char *guid_fetch_field_name;
	struct exmdbc_search_context *search_ctx;

	bool selecting:1;
	bool syncing:1;
	bool initial_sync_done:1;
	bool selected:1;
	bool exists_received:1;
	bool state_fetching_uid1:1;
	bool state_fetched_success:1;
	bool rollback_pending:1;
	bool delayed_untagged_exists:1;
};

struct exmdbc_fetch_request {
	ARRAY(struct exmdbc_mail *) mails;
};

struct exmdbc_untagged_fetch_ctx {
	pool_t pool;

	/* keywords, flags, guid, modseq and fetch_uid may or may not be
	   received with an untagged fetch response */
	ARRAY_TYPE(const_string) keywords;
	/* Is set if have_flags is TRUE */
	enum mail_flags flags;
	const char *guid;
	uint64_t modseq;
	uint32_t fetch_uid;

	/* uid is generated locally based on the remote MSN or fetch_uid */
	uint32_t uid;

	bool have_gmail_labels:1;
	bool have_flags:1;
};

struct exmdbc_copy_request {
	struct exmdbc_save_context *sctx;
	struct seqset_builder *uidset_builder;
};

struct exmdbc_simple_context {
	struct exmdbc_storage_client *client;
	int ret;
};

struct exmdbc_command {

};

extern struct mail_storage exmdbc_storage;

struct exmdb_client *
	exmdbc_client_create();

void exmdbc_storage_client_create(struct mailbox_list *list,
                                  struct exmdbc_storage_client **client_r,
                                  const char **error_r);

void exmdbc_storage_client_unref(struct exmdbc_storage_client **client);
bool exmdbc_storage_client_handle_auth_failure(struct exmdbc_storage_client *client);

struct mail_save_context *
exmdbc_save_alloc(struct mailbox_transaction_context *_t);

struct mailbox *exmdbc_mailbox_alloc(struct mail_storage *storage,
									 struct mailbox_list *list,
									 const char *name,
									 enum mailbox_flags flags);
int exmdbc_save_begin(struct mail_save_context *ctx, struct istream *input);
int exmdbc_save_continue(struct mail_save_context *ctx);
int exmdbc_save_finish(struct mail_save_context *ctx);
void exmdbc_save_cancel(struct mail_save_context *ctx);
int exmdbc_copy(struct mail_save_context *ctx, struct mail *mail);

int exmdbc_transaction_save_commit(struct mailbox_transaction_context *t);
int exmdbc_transaction_save_commit_pre(struct mail_save_context *ctx);
void exmdbc_transaction_save_commit_post(struct mail_save_context *ctx,
					struct mail_index_transaction_commit_result *result);
void exmdbc_transaction_save_rollback(struct mail_save_context *ctx);

void exmdbc_mail_cache_free(struct exmdbc_mail_cache *cache);

bool exmdbc_mail_error_to_resp_text_code(enum mail_error error, const char **str_r);
void exmdbc_copy_error_from_reply(struct exmdbc_storage *storage,
				 enum mail_error default_error,
				 const struct exmdbc_command_reply *reply);
void exmdbc_simple_context_init(struct exmdbc_simple_context *sctx,
			       struct exmdbc_storage_client *client);
void exmdbc_simple_callback(const struct exmdbc_command_reply *reply,
			   void *context);

void exmdbc_untagged_fetch_ctx_free(struct exmdbc_untagged_fetch_ctx **_ctx);
void exmdbc_untagged_fetch_update_flags(struct exmdbc_mailbox *mbox,
				       struct exmdbc_untagged_fetch_ctx *ctx,
				       struct mail_index_view *view,
				       uint32_t lseq);




#endif
