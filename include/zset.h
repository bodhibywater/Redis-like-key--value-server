// zset.h
//
// Sorted set implemented as:
// - AVL tree ordered by (score, key) for range queries
// - Hash map keyed by (key bytes) for O(1) member lookup
//
// Ownership / lifetime:
// - ZSet owns all ZNode allocations.
// - ZNodes are freed by zset_delete() or zset_clear().
// - Keys are stored inline in ZNode as `keylen` bytes plus a trailing NUL for convenience;
//   keylen is authoritative (comparisons do not rely on NUL termination).
//
// Invariants:
// - Every ZNode is present in BOTH structures while live:
//     * in zs->map (by key) and
//     * in zs->root AVL tree (by score,key).
// - Keys are unique at the API level (zset_insert updates existing members).
#ifndef ZSET_H
#define ZSET_H

#include "avltree.h"
#include "hashtable.h"

#include <stddef.h>   // offsetof
#include <stdint.h>
#include <stdbool.h>

// container_of: convert pointer-to-member back to pointer-to-parent struct.
#define container_of(ptr, type, member)((type *)((char *)(ptr) - offsetof(type, member)))

// Sorted set: AVL tree (ordered by score,key) + hash map (lookup by key).
typedef struct {
    AVLNode *root;   // ordered by (score, key)
    HMap map;        // lookup by key
} ZSet;

// One sorted-set element (intrusive in both AVL and hash map).
//
// Field meaning:
// - tree: AVL node linked into ZSet.root (ordered by score,key)
// - hnode: hash node linked into ZSet.map (keyed by key bytes)
// - score: ordering primary key
// - key/keylen: member name (byte string); key is NUL-terminated for convenience only
typedef struct {
    AVLNode tree;
    HNode hnode;
    double score;
    size_t keylen;
    char key[];
} ZNode;

// Initialize an empty set.
void zset_init(ZSet *zs);

// Insert or update member.
// - If key exists: updates score (removes/reinserts in AVL), returns true.
// - If key missing: allocates a new ZNode, inserts into map + AVL.
// Returns false only on allocation failure (ZNode alloc or hash insert).
bool zset_insert(ZSet *zs, const char *key, size_t keylen, double score);

// Lookup by key bytes. Returned pointer is owned by ZSet (do not free).
ZNode *zset_lookup(ZSet *zs, const char *key, size_t keylen);

// Delete a node (removes from both structures, then frees it).
void zset_delete(ZSet *zs, ZNode *zn);

// Free all nodes and reset structures.
void zset_clear(ZSet *zs);

// Inclusive rank range [start, end] with Redis-style negative indices.
// Returns a heap array of ZNode* (caller must free). Sets *out_count.
// Returns NULL with *out_count==0 for empty/out-of-range/oom.
ZNode **zset_range(ZSet *zs, int64_t start, int64_t end, size_t *out_count);

#endif
