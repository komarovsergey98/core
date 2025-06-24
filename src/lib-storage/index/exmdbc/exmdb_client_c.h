#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct exmdb_client;
struct TPROPVAL_ARRAY;

struct exmdbc_folder_dto {
    const char *name;
    uint32_t flags;
    //uint32_t content_count;
    uint64_t folder_id;
};

struct exmdb_folder_metadata {
    uint32_t num_messages;
    uint32_t uidvalidity;
    uint32_t uidnext;
    uint64_t modseq;
    uint64_t folder_id;
};

#define EXMDBC_FIELD_LEN 1024

struct folder_metadata_message {
    uint64_t mid;
    const char *subject;
    const char *from;
    const char *to;
    const char *body_plain;
    const char *body_html;
    uint64_t timestamp;
    uint32_t flags;
};
struct property_metadata {
    uint64_t mid;
    const char *subject;
    const char *from;
    const char *to;
    const char *body_plain;
    const char *body_html;
    uint32_t low_datetime;
    uint64_t timestamp;
    uint32_t flags;
};

// C API

    //TODO: Put username inside of client. Continue refactoring of client
    int exmdb_client_create(struct exmdb_client **client_ptr);

    void exmdb_client_free(struct exmdb_client **client);

    int exmdbc_client_ping_store(const char *dir);

    int exmdbc_client_create_folder_v1(struct exmdb_client *client, const char *dir, int cpid, struct TPROPVAL_ARRAY *pproperties, unsigned long *folder_id);

    int exmdbc_client_get_folders_dtos(struct exmdb_client *client, struct exmdbc_folder_dto *out_array, const char *username, unsigned int max_count, unsigned int *out_count);

    int exmdbc_client_get_folder_dtos(struct exmdb_client *client, uint64_t folder_id, struct exmdb_folder_metadata *dto, const char *username);

    void exmdb_client_set_dir(struct exmdb_client *client, const char *dir);

    int exmdbc_client_fetch_headers(struct exmdb_client *client,
                                const char *username,
                                uint64_t folder_id,
                                uint32_t first_uid,
                                uint32_t last_uid,
                                struct exmdb_message_info *out_messages,
                                unsigned int max_count,
                                unsigned int *out_count);

    int exmdbc_read_message_metadata(const char *dir, const char *username, uint64_t mid, struct folder_metadata_message *out);

    int exmdbc_client_get_folder_messages(struct exmdb_client *client, uint64_t folder_id, struct folder_metadata_message *messages, unsigned int  max_count, const char *username, uint32_t first_uid);

    int exmdbc_client_get_message_properties(struct exmdb_client *client, uint64_t message_id, const char *username, struct property_metadata *meta_out);

    int exmdbc_client_mark_message_read(struct exmdb_client *client, const char *username, uint64_t message_id, int mark_as_read, uint64_t *change_number_out);

#ifdef __cplusplus
}
#endif
