// db.c
//
// Implements DbEntry allocation, lookup, mutation, and destruction.
//
// Hash map contract:
// - Intrusive nodes: DbEntry embeds HNode.
// - Hash is hm_hash_bytes(key,keylen), equality is (keylen + memcmp).
//
// Ownership:
// - DbEntry owns its DbValue payload and releases it in db_entry_free().
//
// Note on OOM behaviour:
// - db_set_str() may return false after clearing an existing value, leaving the key
//   present with `e->v` zeroed (type==0). This is acceptable for this project but
//   is not strong exception safety; a production version would allocate first, then swap.
#include "db.h"

#include <stdlib.h>
#include <string.h>

// Temporary lookup key used for hash-map searches (non-owning).
typedef struct {
    const uint8_t *key;
    uint32_t keylen;
} KeyView;

// Hash helper: compute hcode for arbitrary key bytes.
static uint64_t db_hcode(const uint8_t *key, uint32_t keylen) {
    return hm_hash_bytes(key, keylen);
}

// Hash-map equality predicate: compares stored entry key against a KeyView.
static bool entry_eq_key(const HNode *hn, const void *keyp) {
    const DbEntry *e = container_of(hn, DbEntry, hnode);
    const KeyView *kv = (const KeyView *)keyp;
    return e->keylen == kv->keylen && memcmp(e->key, kv->key, kv->keylen) == 0;
}

// Destructor for DbEntry nodes (invoked by hm_destroy and db_del).
// Must free the active value payload and then the entry itself.
static void db_entry_free(HNode *hn, void *ctx) {
    (void)ctx;
    DbEntry *e = container_of(hn, DbEntry, hnode);

    if (e->v.type == DB_V_STR) {
        free(e->v.as.str.data);
    } else if (e->v.type == DB_V_ZSET) {
        // ZSet owns internal structures; clear before freeing container.
        if (e->v.as.zs) {
			zset_clear(e->v.as.zs);
			free(e->v.as.zs);
		}
    }
    free(e);
}

// Initialize an empty DB.
void db_init(Db *db) {
    hm_init(&db->map);
}

// Destroy DB and free all entries + value payloads.
void db_destroy(Db *db) {
    hm_destroy(&db->map, db_entry_free, NULL);
}

// Lookup an entry by raw key bytes.
// Returns:
// - pointer to DbEntry owned by Db (valid until deletion), or NULL if missing.
DbEntry *db_get(Db *db, const uint8_t *key, uint32_t keylen) {
    KeyView kv = { .key = key, .keylen = keylen };
    uint64_t h = db_hcode(key, keylen);

    HNode *hn = hm_get(&db->map, h, &kv, entry_eq_key);
    return hn ? container_of(hn, DbEntry, hnode) : NULL;
}

// Allocate a new DbEntry and copy the key bytes inline.
// Note: key is NUL-terminated for convenience, but keylen is authoritative.
static DbEntry *db_entry_new(const uint8_t *key, uint32_t keylen) {
    DbEntry *e = (DbEntry *)malloc(sizeof(DbEntry) + (size_t)keylen + 1);
    if (!e) return NULL;

    e->hnode.next = NULL;
    e->hnode.hcode = db_hcode(key, keylen);
    e->keylen = keylen;

    memcpy(e->key, key, keylen);
    e->key[keylen] = '\0';

    memset(&e->v, 0, sizeof(e->v));
    return e;
}

// Set key to a string value (deep copy of val bytes).
//
// Behaviour:
// - Creates entry if missing.
// - Overwrites any existing value, freeing old payload.
//
// Important caveat (current implementation):
// - If allocation for the new value fails (OOM), this returns false *after* clearing
//   the previous value. The key may be left present with `v` zeroed (type==0).
bool db_set_str(Db *db, const uint8_t *key, uint32_t keylen, const uint8_t *val, uint32_t vallen) {
    DbEntry *e = db_get(db, key, keylen);

    if (!e) {
        e = db_entry_new(key, keylen);
        if (!e) return false;
        if (!hm_put(&db->map, &e->hnode)) {
            free(e);
            return false;
        }
    } else {
        // overwrite existing value: free old content
        if (e->v.type == DB_V_STR) {
            free(e->v.as.str.data);
        } else if (e->v.type == DB_V_ZSET) {
            if (e->v.as.zs) {
				zset_clear(e->v.as.zs);
				free(e->v.as.zs);
			}
        }
		memset(&e->v, 0, sizeof(e->v));
    }

    uint8_t *copy = NULL;
    if (vallen > 0) {
        copy = (uint8_t *)malloc(vallen);
        if (!copy) return false;
        memcpy(copy, val, vallen);
    }

    e->v.type = DB_V_STR;
    e->v.as.str.data = copy;
    e->v.as.str.len = vallen;
    return true;
}

// Delete key if present.
//
// Returns true if an entry was removed, false if key was absent.
bool db_del(Db *db, const uint8_t *key, uint32_t keylen) {
    KeyView kv = { .key = key, .keylen = keylen };
    uint64_t h = db_hcode(key, keylen);

    HNode *hn = hm_pop(&db->map, h, &kv, entry_eq_key);
    if (!hn) return false;

    db_entry_free(hn, NULL);
    return true;
}

// Get existing zset or create it if missing.
//
// Returns:
// - DBZ_OK   : *out_zs set to a valid zset
// - DBZ_TYPE : key exists but holds a non-zset value
// - DBZ_OOM  : allocation failed (function rolls back partial insertions)
DbZRes db_get_or_create_zset(Db *db, const uint8_t *key, uint32_t keylen, ZSet **out_zs) {
    DbEntry *e = db_get(db, key, keylen);

    if (!e) {
        e = db_entry_new(key, keylen);
        if (!e) return DBZ_OOM;

        if (!hm_put(&db->map, &e->hnode)) {
            free(e);
            return DBZ_OOM;
        }

        ZSet *zs = (ZSet *)malloc(sizeof(ZSet));
        if (!zs) {
            // Roll back: avoid leaving a key present with an uninitialized value.
            (void)db_del(db, key, keylen);
            return DBZ_OOM;
        }
        zset_init(zs);

        e->v.type = DB_V_ZSET;
        e->v.as.zs = zs;
        *out_zs = zs;
        return DBZ_OK;
    }

    if (e->v.type != DB_V_ZSET) return DBZ_TYPE;

    *out_zs = e->v.as.zs;
    return DBZ_OK;
}
