// hashtable.h
//
// Intrusive hash map with separate chaining + incremental rehashing.
//
// Data model:
// - Callers embed an HNode inside their own struct.
// - node->hcode must be set by the caller (typically hm_hash_bytes / hm_hash_cstr).
//
// Rehashing:
// - ht[0] is the active table.
// - ht[1] is allocated only during rehash (when load factor exceeds threshold).
// - While rehashing, entries may exist in either table; lookups/removals search both.
// - rehash_idx is the next bucket index in ht[0] to migrate into ht[1].
// - hm_rehash_step() migrates a small number of buckets per operation (amortised).
//
// Important invariants / caveats:
// - hm_put() always inserts; it does NOT check for duplicates. The caller must ensure
//   a key is not already present (or explicitly remove it first).
// - This is single-threaded code; no internal synchronization.
#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Intrusive node stored in the hash map.
// - next is owned/managed by the map.
// - hcode caches the hash of the key to avoid recomputation.
typedef struct HNode {
    struct HNode *next;
    uint64_t hcode;
} HNode;

// Equality predicate used for lookup/removal.
// Must return true iff `node`'s key equals `key` (key is caller-defined).
typedef bool (*hm_eq_key_fn)(const HNode *node, const void *key);

// Optional destructor callback used by hm_destroy() to free user-owned containers.
typedef void (*hm_free_node_fn)(HNode *node, void *ctx);

// One hash table (bucket array).
// Invariant: nbuckets is a power-of-two and mask == nbuckets - 1.
typedef struct HTable {
    HNode **buckets;    // Array of bucket heads
    size_t nbuckets;    // power of two
    size_t mask;        // nbuckets - 1
    size_t size;        // number of nodes stored in this table
} HTable;

// Hash map wrapper supporting incremental rehash via two tables.
// Invariant: ht[1].buckets != NULL iff rehashing is in progress.
typedef struct HMap {
    HTable ht[2];       // ht[0] active, ht[1] new table during rehash
    size_t rehash_idx;  // next bucket index to migrate in ht[0]
} HMap;

/* ---- Hash helpers ---- */
uint64_t hm_hash_bytes(const void *data, size_t len);
uint64_t hm_hash_cstr(const char *s);

/* ---- Lifecycle ---- */
void hm_init(HMap *m);
void hm_destroy(HMap *m, hm_free_node_fn free_node, void *ctx);

/* ---- Introspection ---- */
size_t hm_size(const HMap *m);
bool hm_is_rehashing(const HMap *m);

/* ---- Core ops ---- */
// Insert node into the map (node->hcode must be set).
// Returns false only if the initial bucket allocation fails (OOM).
// Note: does NOT check for duplicates.
bool hm_put(HMap *m, HNode *node);

// Lookup/remove by (hcode, key, eq)
HNode *hm_get(HMap *m, uint64_t hcode, const void *key, hm_eq_key_fn eq);
HNode *hm_pop(HMap *m, uint64_t hcode, const void *key, hm_eq_key_fn eq);

// Do N buckets worth of rehash work (amortised). Safe to call any time.
void hm_rehash_step(HMap *m, size_t nsteps);

#endif
