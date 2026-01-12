// hashtable.c
//
// Implementation notes:
// - Separate chaining buckets (linked lists).
// - Load factor threshold is controlled by HM_MAX_LOAD_{NUM,DEN}.
// - Rehashing is incremental using two tables (ht[0] -> ht[1]).
//   Each operation performs HM_REHASH_WORK buckets of migration to amortize cost.
//
// Failure policy:
// - If starting a rehash fails due to OOM, the map continues operating without rehash.
//   Correctness is preserved; performance may degrade (longer chains).
#include "hashtable.h"

#include <stdlib.h>
#include <string.h>

// Initial bucket count for the first insertion.
#define HM_INIT_BUCKETS 8u

// Start rehash when size/nbuckets exceeds (HM_MAX_LOAD_NUM/HM_MAX_LOAD_DEN).
// With 1/1, this triggers when size > nbuckets.
#define HM_MAX_LOAD_NUM 1u
#define HM_MAX_LOAD_DEN 1u

// Buckets migrated per operation while rehashing (amortised).
#define HM_REHASH_WORK  1u      // buckets migrated per op

static inline bool is_pow2(size_t x) { return x && ((x & (x - 1)) == 0); }

// Reset table to an empty, non-allocated state.
static void htable_reset(HTable *t) {
    t->buckets = NULL;
    t->nbuckets = 0;
    t->mask = 0;
    t->size = 0;
}

// Allocate and initialize a bucket array of power-of-two size.
static bool htable_init(HTable *t, size_t nbuckets) {
    if (!is_pow2(nbuckets)) return false;
    HNode **b = (HNode **)calloc(nbuckets, sizeof(HNode *));
    if (!b) return false;
    t->buckets = b;
    t->nbuckets = nbuckets;
    t->mask = nbuckets - 1;
    t->size = 0;
    return true;
}

static void htable_free_buckets(HTable *t) {
    free(t->buckets);
    htable_reset(t);
}

// Map hash code to bucket index. Requires power-of-two nbuckets (mask = nbuckets-1).
static inline size_t bucket_index(const HTable *t, uint64_t hcode) {
    return (size_t)(hcode & (uint64_t)t->mask);
}

static void maybe_start_rehash(HMap *m);

// 64-bit FNV-1a hash over raw bytes. Used to populate HNode.hcode.
uint64_t hm_hash_bytes(const void *data, size_t len) {
    // 64-bit FNV-1a
    const unsigned char *p = (const unsigned char *)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

uint64_t hm_hash_cstr(const char *s) {
    return hm_hash_bytes(s, strlen(s));
}

// Initialize map to empty. Buckets are allocated lazily on first insertion.
void hm_init(HMap *m) {
    htable_reset(&m->ht[0]);
    htable_reset(&m->ht[1]);
    m->rehash_idx = 0;
    // lazily allocate on first insert to keep init cheap
}

// Destroy the map.
// - If free_node is provided, it is called once per node (after unlinking from chains).
// - Always frees the bucket arrays for ht[0] and ht[1] (if allocated).
void hm_destroy(HMap *m, hm_free_node_fn free_node, void *ctx) {
    for (int ti = 0; ti < 2; ti++) {
        HTable *t = &m->ht[ti];
        if (!t->buckets) continue;

        if (free_node) {
            for (size_t i = 0; i < t->nbuckets; i++) {
                HNode *cur = t->buckets[i];
                while (cur) {
                    HNode *next = cur->next;
                    cur->next = NULL;
                    free_node(cur, ctx);
                    cur = next;
                }
            }
        }
        htable_free_buckets(t);
    }
    m->rehash_idx = 0;
}

size_t hm_size(const HMap *m) {
    return m->ht[0].size + m->ht[1].size;
}

bool hm_is_rehashing(const HMap *m) {
    return m->ht[1].buckets != NULL;
}

// Insert node at bucket head without duplicate checks.
// Precondition: t->buckets is allocated and node is not currently linked in any table.
static void htable_insert_raw(HTable *t, HNode *node) {
    size_t idx = bucket_index(t, node->hcode);
    node->next = t->buckets[idx];
    t->buckets[idx] = node;
    t->size++;
}

// Find the pointer-to-pointer slot for (hcode,key) within table `t`.
// Returns NULL if not found (or if table is unallocated).
// The returned slot can be used for in-place removal.
static HNode **htable_find_slot(HTable *t, uint64_t hcode, const void *key, hm_eq_key_fn eq) {
    if (!t->buckets) return NULL;
    size_t idx = bucket_index(t, hcode);
    HNode **pp = &t->buckets[idx];
    while (*pp) {
        HNode *n = *pp;
        if (n->hcode == hcode && eq(n, key)) {
            return pp;
        }
        pp = &n->next;
    }
    return NULL;
}

// Perform up to nsteps buckets of rehash work.
//
// While rehashing:
// - Buckets [0 .. rehash_idx) in ht[0] have already been migrated (emptied).
// - Entries may live in ht[0] (not yet migrated buckets) or ht[1] (new table).
//
// Completion:
// - When all buckets are migrated, ht[1] becomes the active table and the old
//   bucket array is freed.
void hm_rehash_step(HMap *m, size_t nsteps) {
    if (!hm_is_rehashing(m)) return;

    HTable *old = &m->ht[0];
    HTable *newt = &m->ht[1];

    while (nsteps--) {
        // advance to next non-empty bucket
        while (m->rehash_idx < old->nbuckets && old->buckets[m->rehash_idx] == NULL) {
            m->rehash_idx++;
        }
        if (m->rehash_idx >= old->nbuckets) {
            // done: new becomes active
            htable_free_buckets(old);
            m->ht[0] = *newt;
            htable_reset(newt);
            m->rehash_idx = 0;
            return;
        }

        // migrate bucket
        HNode *cur = old->buckets[m->rehash_idx];
        old->buckets[m->rehash_idx] = NULL;

        while (cur) {
            HNode *next = cur->next;
            cur->next = NULL;
            old->size--;            // leaving old
            htable_insert_raw(newt, cur);
            cur = next;
        }

        m->rehash_idx++;
    }
}

// Start rehashing if load factor exceeds threshold.
// Allocates ht[1] at double the bucket count; on OOM, rehashing is skipped.
static void maybe_start_rehash(HMap *m) {
    if (hm_is_rehashing(m)) return;
    HTable *t = &m->ht[0];

    if (!t->buckets) return;
    // size / nbuckets > MAX_LOAD => start rehash
    if (t->size * HM_MAX_LOAD_DEN <= t->nbuckets * HM_MAX_LOAD_NUM) return;

    size_t new_buckets = t->nbuckets * 2;
    if (!htable_init(&m->ht[1], new_buckets)) {
        // OOM: keep running without rehash (performance degrades, but correctness ok)
        htable_reset(&m->ht[1]);
        return;
    }
    m->rehash_idx = 0;
}

// Insert node into the map.
// - Lazily allocates ht[0] on first insert.
// - Performs a small amount of rehash work (if rehashing).
// - Inserts into ht[1] when rehashing, else into ht[0].
// - May start a rehash after insertion if load factor exceeds threshold.
//
// Note: no duplicate detection; callers must enforce uniqueness externally.
bool hm_put(HMap *m, HNode *node) {
    if (!m->ht[0].buckets && !htable_init(&m->ht[0], HM_INIT_BUCKETS)) {
        return false;
    }

    // do amortised rehash work
    hm_rehash_step(m, HM_REHASH_WORK);

    // insert into new table if rehashing, else active
    HTable *dst = hm_is_rehashing(m) ? &m->ht[1] : &m->ht[0];
    htable_insert_raw(dst, node);

    maybe_start_rehash(m);
    return true;
}

// Lookup by (hcode,key).
// While rehashing, searches ht[0] first and then ht[1].
HNode *hm_get(HMap *m, uint64_t hcode, const void *key, hm_eq_key_fn eq) {
    if (!m->ht[0].buckets) return NULL;

    hm_rehash_step(m, HM_REHASH_WORK);

    // search ht[0], and ht[1] if rehashing
    HNode **slot = htable_find_slot(&m->ht[0], hcode, key, eq);
    if (slot) return *slot;

    if (hm_is_rehashing(m)) {
        slot = htable_find_slot(&m->ht[1], hcode, key, eq);
        if (slot) return *slot;
    }
    return NULL;
}

// Remove and return a node by (hcode,key) from a single table.
// Updates t->size and unlinks node->next.
static HNode *htable_pop(HTable *t, uint64_t hcode, const void *key, hm_eq_key_fn eq) {
    HNode **slot = htable_find_slot(t, hcode, key, eq);
    if (!slot) return NULL;
    HNode *n = *slot;
    *slot = n->next;
    n->next = NULL;
    t->size--;
    return n;
}

// Remove and return a node by (hcode,key).
// While rehashing, attempts ht[0] first, then ht[1].
HNode *hm_pop(HMap *m, uint64_t hcode, const void *key, hm_eq_key_fn eq) {
    if (!m->ht[0].buckets) return NULL;

    hm_rehash_step(m, HM_REHASH_WORK);

    HNode *n = htable_pop(&m->ht[0], hcode, key, eq);
    if (n) return n;

    if (hm_is_rehashing(m)) {
        return htable_pop(&m->ht[1], hcode, key, eq);
    }
    return NULL;
}
