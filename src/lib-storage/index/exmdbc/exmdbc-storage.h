#ifndef EXMDBC_STORAGE_H
#define EXMDBC_STORAGE_H

#include "index-storage.h"

#define EXMDBC_STORAGE_NAME "exmdbc"

#define EXMDBC_STORAGE(s)	container_of(s, struct exmdbc_storage, storage)
#define EXMDBC_MAILBOX(s)	container_of(s, struct exmdbc_mailbox, box)

struct exmdbc_mailbox;

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
	uint64_t folder_id;

	// struct mail_index_transaction *delayed_sync_trans;
	struct mail_index_view *sync_view;
	struct timeout *to_idle_check, *to_idle_delay;

	enum mail_flags permanent_flags;
	uint32_t highest_nonrecent_uid;

	ARRAY(uint64_t) rseq_modseqs;
	uint32_t sync_uid_validity;
	uint32_t sync_uid_next;
	uint64_t sync_highestmodseq;
	uint32_t sync_fetch_first_uid;
	uint32_t exists_count;
	uint32_t min_append_uid;
	char *sync_gmail_pop3_search_tag;

	/* keep the previous fetched message body cached,
	   mainly for partial IMAP fetches */
	struct exmdbc_mail_cache prev_mail_cache;

	uint32_t prev_skipped_rseq, prev_skipped_uid;

	const char *guid_fetch_field_name;
	struct exmdbc_search_context *search_ctx;

	bool selecting:1;
	bool syncing:1;
	bool initial_sync_done:1;
	bool selected:1;
	bool exists_received:1;
	bool state_fetching_uid1:1;
};

// struct exmdbc_untagged_fetch_ctx {
// 	pool_t pool;
//
// 	/* keywords, flags, guid, modseq and fetch_uid may or may not be
// 	   received with an untagged fetch response */
// 	ARRAY_TYPE(const_string) keywords;
// 	/* Is set if have_flags is TRUE */
// 	enum mail_flags flags;
// 	const char *guid;
// 	uint64_t modseq;
// 	uint32_t fetch_uid;
//
// 	/* uid is generated locally based on the remote MSN or fetch_uid */
// 	uint32_t uid;
//
// 	bool have_gmail_labels:1;
// 	bool have_flags:1;
// };

struct exmdbc_copy_request {
	struct exmdbc_save_context *sctx;
	struct seqset_builder *uidset_builder;
};

extern struct mail_storage exmdbc_storage;

struct exmdb_client *
	exmdbc_client_create();

void exmdbc_storage_client_create(struct mailbox_list *list,
                                  struct exmdbc_storage_client **client_r,
                                  const char **error_r);

void exmdbc_storage_client_unref(struct exmdbc_storage_client **client);

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

int exmdbc_transaction_save_commit_pre(struct mail_save_context *ctx);
void exmdbc_transaction_save_commit_post(struct mail_save_context *ctx,
					struct mail_index_transaction_commit_result *result);
void exmdbc_transaction_save_rollback(struct mail_save_context *ctx);

void exmdbc_mail_cache_free(struct exmdbc_mail_cache *cache);


#endif
