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
};

// C API

    int exmdb_client_create(struct exmdb_client **client_ptr);

    void exmdb_client_free(struct exmdb_client **client);

    int exmdbc_client_ping_store(struct exmdb_client *c, const char *dir);

    int exmdbc_client_create_folder_v1(struct exmdb_client *client, const char *dir, int cpid, struct TPROPVAL_ARRAY *pproperties, unsigned long *folder_id);

    int exmdbc_client_get_folder_dtos(struct exmdb_client *client, struct exmdbc_folder_dto *out_array, const char *username, unsigned int max_count, unsigned int *out_count);

    void exmdb_client_set_dir(struct exmdb_client *client, const char *dir);


#ifdef __cplusplus
}
#endif
