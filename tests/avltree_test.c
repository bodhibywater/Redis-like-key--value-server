#include "avltree.h"

#include <assert.h>
#include <stddef.h>  // offsetof
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    AVLNode n;
    int key;
} IntNode;

static int intnode_cmp(const AVLNode *a, const AVLNode *b) {
    // Comparator for avl_insert, converts AVLNode* back to IntNode* using offsetof() math
    // Then compares keys
    const IntNode *ia = (const IntNode *)((const char *)a - offsetof(IntNode, n));
    const IntNode *ib = (const IntNode *)((const char *)b - offsetof(IntNode, n));
    if (ia->key < ib->key) return -1;
    if (ia->key > ib->key) return 1;
    return 0;
}

static void shuffle(int *arr, size_t n) {
    // Deterministic shuffle (fixed seed) so test is stable.
    srand(12345);
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)(rand() % (int)(i + 1));
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

static void sanity_check_parents(const AVLNode *root) {
    // Recursive invariant check
    if (!root) return;
    if (root->left)  assert(root->left->parent == root);
    if (root->right) assert(root->right->parent == root);
    sanity_check_parents(root->left);
    sanity_check_parents(root->right);
}

int main(void) {
    // Allocates 256 keys then shuffles them
    enum { N = 256 };
    IntNode *nodes = calloc(N, sizeof(*nodes));
    assert(nodes);
    int keys[N];
    for (int i = 0; i < N; i++) keys[i] = i;
    shuffle(keys, N);

    // Inserts keys one by one
    AVLNode *root = NULL;
    for (int i = 0; i < N; i++) {
        int k = keys[i];
        nodes[k].key = k;
        root = avl_insert(root, &nodes[k].n, intnode_cmp);
        assert(root);
        assert(root->parent == NULL);
    }

    // Checks invariants
    assert(avl_count(root) == N);
    sanity_check_parents(root);

    // In-order traversal (to check ordering) should yield 0..N-1.
    AVLNode *cur = avl_min(root);
    for (int expect = 0; expect < N; expect++) {
        assert(cur);
        const IntNode *in = (const IntNode *)((const char *)cur - offsetof(IntNode, n));
        assert(in->key == expect);
        cur = avl_next(cur);
    }
    assert(cur == NULL);

    puts("avltree_test: OK");
    free(nodes);
    return 0;
}
