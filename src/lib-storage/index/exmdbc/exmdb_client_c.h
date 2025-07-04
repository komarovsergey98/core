#pragma once


#ifdef __cplusplus
extern "C" {

#include <time.h>
#include <stdint.h>

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

struct message_properties {
    uint64_t mid;
    const char *from_name;
    const char *from_email;
    const char *to_name;
    const char *to_email;
    const char *cc;
    const char *bcc;
    const char *subject;
    const char *reply_recipment;
    const char *reply_to;
    const char *msg_id;
    time_t submited_time;
    time_t delivery_time;

    const char *message_header;

    const char *body_plain;
    const char *body_html;
    uint32_t body_size;

    uint32_t flags;
    uint32_t size;
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

    int exmdbc_read_message_metadata(uint64_t message_id, struct TPROPVAL_ARRAY *props, struct message_properties *msgs_props);

    int exmdbc_client_get_folder_messages(struct exmdb_client *client, uint64_t folder_id, struct message_properties *messages, unsigned int  max_count, const char *username, uint32_t first_uid);

    int exmdbc_client_get_message_properties(struct exmdb_client *client, uint64_t folder_id, uint64_t message_id, const char *username, struct message_properties *msgs_props);

    int exmdbc_client_mark_message_read(struct exmdb_client *client, const char *username, uint64_t message_id, int mark_as_read, uint64_t *change_number_out);

    int exmdbc_client_save_message( struct exmdb_client *client, uint64_t folder_id, const char *username, const struct message_properties *props);

    int exmdbc_client_save_body( struct exmdb_client *client, uint64_t folder_id, const char *username, const void *body, size_t body_len);

#ifdef __cplusplus
}
#endif
