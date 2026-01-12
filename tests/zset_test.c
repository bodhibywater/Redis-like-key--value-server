#include "zset.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void must_zadd(ZSet *zs, const char *key, double score) {
    bool ok = zset_insert(zs, key, strlen(key), score);
    assert(ok);
}

static void must_zdel(ZSet *zs, const char *key) {
    ZNode *zn = zset_lookup(zs, key, strlen(key));
    assert(zn);
    zset_delete(zs, zn);
}

static void assert_range_keys(ZSet *zs, int64_t start, int64_t end, const char **expect, size_t n_expect) {
    size_t n = 0;
    ZNode **out = zset_range(zs, start, end, &n);

    // Asserts size of zrange command and correct ordering
    assert(n == n_expect);
    for (size_t i = 0; i < n; i++) {
        ZNode *z = out[i];
        assert(z);
        assert(z->keylen == strlen(expect[i]));
        assert(memcmp(z->key, expect[i], z->keylen) == 0);
    }

    free(out);
}

int main(void) {
    ZSet zs;
    zset_init(&zs);

    // Mix scores + tie scores.
    // For equal scores, ordering must be by key (lexicographic) because AVL cmp uses (score, key).
    must_zadd(&zs, "c", 1.0);
    must_zadd(&zs, "a", 1.0);
    must_zadd(&zs, "b", 1.0);
    must_zadd(&zs, "x", 0.5);
    must_zadd(&zs, "y", 2.0);

    // Full order should be: x(0.5), a(1.0), b(1.0), c(1.0), y(2.0)
    {
        const char *exp[] = {"x", "a", "b", "c", "y"};
        assert_range_keys(&zs, 0, -1, exp, 5);
    }

    // Negative start/end indexing: last 2 => c, y
    {
        const char *exp[] = {"c", "y"};
        assert_range_keys(&zs, -2, -1, exp, 2);
    }

    // End clamping: ask beyond range
    {
        const char *exp[] = {"b", "c", "y"};
        assert_range_keys(&zs, 2, 999, exp, 3);
    }

    // Empty range: end < start
    {
        size_t n = 123;
        ZNode **out = zset_range(&zs, 3, 2, &n);
        assert(out == NULL);
        assert(n == 0);
    }

    // Update existing member: change score and ensure it moves.
    // Move "b" from 1.0 to 3.0: order becomes x, a, c, y, b
    {
        bool ok = zset_insert(&zs, "b", 1, 3.0);
        assert(ok);

        const char *exp[] = {"x", "a", "c", "y", "b"};
        assert_range_keys(&zs, 0, -1, exp, 5);
    }

    // Delete member and verify.
    {
        must_zdel(&zs, "a");

        const char *exp[] = {"x", "c", "y", "b"};
        assert_range_keys(&zs, 0, -1, exp, 4);
    }

    zset_clear(&zs);
    puts("zset_test: OK");
    return 0;
}
