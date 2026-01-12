// db.h
//
// In-memory key/value database built on an intrusive hash map (HMap).
//
// Storage model / invariants:
// - Keys are stored inline in each DbEntry as `keylen` raw bytes.
//   The trailing NUL is for convenience/debugging only; `keylen` is authoritative.
// - Values are tagged (DbValueType) and owned by the DbEntry.
//   DB_V_STR  -> heap buffer (data,len). Bytes are not NUL-terminated.
//   DB_V_ZSET -> heap ZSet* (zset_clear + free on deletion).
//
// Lifetime:
// - db_get() returns a DbEntry* owned by the DB, valid until that key is deleted
//   (db_del) or the DB is destroyed (db_destroy).
#ifndef DB_H
#define DB_H

#include "hashtable.h"
#include "zset.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Discriminant for DbValue's union payload.
typedef enum {
    DB_V_STR = 1,
    DB_V_ZSET = 2,
} DbValueType;

// Tagged value. The active union member is selected by `type`.
typedef struct {
    DbValueType type;
    union {
        struct {
            uint8_t *data;
            uint32_t len;
        } str;
        ZSet *zs;
    } as;
} DbValue;

// One DB entry stored in the hash map.
// Invariant: hnode.hcode == hash(key,keylen) and keylen matches stored key bytes.
typedef struct DbEntry {
    HNode hnode;
    uint32_t keylen;
    DbValue v;
    char key[];   // inline, NUL-terminated for convenience
} DbEntry;

// Database handle: a single hash map of DbEntry nodes.
typedef struct {
    HMap map;
} Db;

// Result codes for zset access/creation helper.
typedef enum {
    DBZ_OK = 0,
    DBZ_OOM = 1,
    DBZ_TYPE = 2,
} DbZRes;

void db_init(Db *db);
void db_destroy(Db *db);

DbEntry *db_get(Db *db, const uint8_t *key, uint32_t keylen);
bool db_set_str(Db *db, const uint8_t *key, uint32_t keylen, const uint8_t *val, uint32_t vallen);
bool db_del(Db *db, const uint8_t *key, uint32_t keylen);

// Get existing zset or create it if missing.
// - Returns DBZ_TYPE if key exists but is not a zset.
// - On DBZ_OK, *out_zs is set to a valid ZSet* owned by the DB.
DbZRes db_get_or_create_zset(Db *db, const uint8_t *key, uint32_t keylen, ZSet **out_zs);

#endif
