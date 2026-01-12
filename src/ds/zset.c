// zset.c
//
// ZSet implementation backed by:
// - HMap: key -> ZNode (unique membership by key bytes)
// - AVL: ordered by (score, key) for deterministic ordering and range-by-rank
//
// Important invariants:
// - Live nodes exist in both structures.
// - AVL ordering is total order: (score, key bytes). Key is used to break score ties.
// - zset_clear() frees nodes via the AVL tree, then frees hash buckets WITHOUT walking
//   node chains (hm_destroy(..., free_node=NULL)), avoiding touching freed nodes.
#include "zset.h"

#include <stdlib.h>
#include <string.h>

// Non-owning lookup key passed into hm_get/hm_pop predicates.
typedef struct {
    const char *key;
    size_t keylen;
} ZKeyView;

// Compute hash code for key bytes (delegates to hm_hash_bytes).
// Note: HNode.hcode is cached in each ZNode at creation time.
static uint64_t zset_hcode(const char *key, size_t keylen) {
    return hm_hash_bytes(key, keylen);
}

// Lexicographic compare for byte strings (length-aware, not NUL-terminated).
static int key_cmp(const char *a, size_t alen, const char *b, size_t blen) {
    size_t n = (alen < blen) ? alen : blen;
    int c = memcmp(a, b, n);
    if (c != 0) return c;
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

// Hash-map equality predicate: compare stored node key against ZKeyView.
static bool znode_eq_key(const HNode *hn, const void *keyp) {
    const ZNode *zn = container_of(hn, ZNode, hnode);
    const ZKeyView *kv = (const ZKeyView *)keyp;

    return zn->keylen == kv->keylen && memcmp(zn->key, kv->key, kv->keylen) == 0;
}

// AVL comparator: order by (score, key).
// Key breaks ties to ensure deterministic ordering among equal scores.
static int znode_cmp_avl(const AVLNode *a, const AVLNode *b) {
    const ZNode *za = container_of(a, ZNode, tree);
    const ZNode *zb = container_of(b, ZNode, tree);

    if (za->score < zb->score) return -1;
    if (za->score > zb->score) return 1;

    return key_cmp(za->key, za->keylen, zb->key, zb->keylen);
}

// Allocate and initialize a new ZNode:
// - initializes intrusive nodes (AVL node + HNode)
// - copies key bytes inline and appends a trailing NUL for convenience
// Returns NULL on OOM.
static ZNode *create_znode(const char *key, size_t keylen, double score) {
    ZNode *zn = (ZNode *)malloc(sizeof(ZNode) + keylen + 1);
    if (!zn) return NULL;

    // Intrusive nodes: AVL links are initialized; HNode caches the hash.
    avl_node_init(&zn->tree);
    zn->hnode.next = NULL;
    zn->hnode.hcode = zset_hcode(key, keylen);

    zn->score = score;
    zn->keylen = keylen;

    memcpy(zn->key, key, keylen);
    zn->key[keylen] = '\0'; // convenience for printing/debug; comparisons use keylen
    return zn;
}

void zset_init(ZSet *zs) {
    zs->root = NULL;
    hm_init(&zs->map);
}

// Lookup member by key bytes using the hash map.
// Returns pointer owned by ZSet, or NULL if missing.
ZNode *zset_lookup(ZSet *zs, const char *key, size_t keylen) {
    ZKeyView kv = { .key = key, .keylen = keylen };
    uint64_t h = zset_hcode(key, keylen);

    HNode *hn = hm_get(&zs->map, h, &kv, znode_eq_key);
    return hn ? container_of(hn, ZNode, hnode) : NULL;
}

// Insert or update.
// - Update path: remove node from AVL (ordering depends on score), update score,
//   then reinsert into AVL. Hash map entry remains unchanged.
// - Insert path: allocate node, insert into hash map, then insert into AVL.
// Returns false only on allocation failure.
bool zset_insert(ZSet *zs, const char *key, size_t keylen, double score) {
    ZNode *zn = zset_lookup(zs, key, keylen);

    if (zn) {
        // Update existing: remove from AVL, update score, reinsert
        zs->root = avl_remove(zs->root, &zn->tree);
        zn->score = score;
        zs->root = avl_insert(zs->root, &zn->tree, znode_cmp_avl);
        return true;
    }

    zn = create_znode(key, keylen, score);
    if (!zn) return false;

    if (!hm_put(&zs->map, &zn->hnode)) {
        free(zn);
        return false;
    }

    zs->root = avl_insert(zs->root, &zn->tree, znode_cmp_avl);
    return true;
}

void zset_delete(ZSet *zs, ZNode *zn) {
    if (!zn) return;

    ZKeyView kv = { .key = zn->key, .keylen = zn->keylen };

    // Remove from hashmap
    (void)hm_pop(&zs->map, zn->hnode.hcode, &kv, znode_eq_key);

    // Remove from AVL
    zs->root = avl_remove(zs->root, &zn->tree);

    free(zn);
}

// Delete a node from both structures and free it.
// Safe to call with NULL (no-op).
static void zset_free_subtree(AVLNode *n) {
    if (!n) return;
    zset_free_subtree(n->left);
    zset_free_subtree(n->right);
    ZNode *zn = container_of(n, ZNode, tree);
    free(zn);
}

// Free all nodes and reset the set.
// Order matters:
// 1) free nodes via AVL traversal
// 2) free hash bucket arrays without iterating nodes (free_node=NULL)
// 3) re-init map for reuse
void zset_clear(ZSet *zs) {
    // free nodes via tree (owns the nodes)
    zset_free_subtree(zs->root);
    zs->root = NULL;

    // free hash buckets; nodes already freed
    hm_destroy(&zs->map, NULL, NULL);
    hm_init(&zs->map);
}

// Return inclusive rank range [start,end] (0-based) with Redis-style negative indices.
// Uses subtree counts (avl_count + avl_at_rank) and successor iteration (avl_next).
//
// Ownership:
// - Returns a heap-allocated array of ZNode*; caller must free() it.
// - Nodes themselves remain owned by ZSet.
ZNode **zset_range(ZSet *zs, int64_t start, int64_t end, size_t *out_count) {
    if (!out_count) return NULL;

    size_t total = avl_count(zs->root);
    if (total == 0) {
        *out_count = 0;
        return NULL;
    }

    // support negative indices
    if (start < 0) start += (int64_t)total;
    if (end   < 0) end   += (int64_t)total;

    if (start < 0) start = 0;
    if (end < 0) {
        *out_count = 0;
        return NULL;
    }

    if ((size_t)start >= total || start > end) {
        *out_count = 0;
        return NULL;
    }

    if ((size_t)end >= total) end = (int64_t)total - 1;

    size_t want = (size_t)(end - start + 1);
    ZNode **results = (ZNode **)malloc(want * sizeof(*results));
    if (!results) {
        *out_count = 0;
        return NULL;
    }

    // Start at the node with rank `start`, then walk successors.
    AVLNode *n = avl_at_rank(zs->root, start);
    size_t i = 0;
    while (n && i < want) {
        results[i++] = container_of(n, ZNode, tree);
        n = avl_next(n);
    }

    *out_count = i;
    return results;
}
