// avltree.h
//
// Intrusive AVL tree with parent pointers and subtree metadata.
//
// Intrusive means:
// - The caller allocates/owns AVLNode storage (no malloc/free inside the AVL layer).
// - The AVL layer only links/unlinks nodes and maintains invariants.
//
// Metadata invariants (per node n):
// - n->height = 1 + max(height(left), height(right))        (empty child height = 0)
// - n->count  = 1 + count(left) + count(right)              (empty child count  = 0)
// - Balance factor bf = height(left) - height(right) is in {-1,0,1} for AVL validity.
//
// Ordering:
// - Ordering is defined by the comparator passed to avl_insert().
// - This module does not enforce "no duplicates"; the comparator's behaviour on equality
//   determines placement (this implementation inserts "equal" into the right subtree).
#ifndef AVLTREE_H
#define AVLTREE_H

#include <stdint.h>
#include <stdlib.h>

// Base node for an AVL tree.
//
// Parent pointers are maintained for all linked nodes:
// - root->parent == NULL
// - if n->left  != NULL then n->left->parent  == n
// - if n->right != NULL then n->right->parent == n
typedef struct AVLNode {
    struct AVLNode *left;
    struct AVLNode *right;
    struct AVLNode *parent;
    uint32_t height;                // Subtree height
    uint32_t count;                 // Subtree node count
} AVLNode;

// Intrusive: caller owns memory for nodes.
static inline void avl_node_init(AVLNode *n) {
    n->left = n->right = n->parent = NULL;
    n->height = 1;
    n->count = 1;
}

static inline uint32_t avl_height(const AVLNode *n) { return n ? n->height : 0; }
static inline uint32_t avl_count (const AVLNode *n) { return n ? n->count  : 0; }

// Recompute height/count from children.
void avl_recalc(AVLNode *n);

// Restore AVL invariants starting at `n` and walking up to the root.
// Returns the (possibly new) root pointer.
AVLNode *avl_fix_up(AVLNode *n);

// Insert `node` into the tree using comparator ordering.
// Precondition: node is not currently linked into any tree.
// Returns the (possibly new) root pointer.
AVLNode *avl_insert(AVLNode *root, AVLNode *node, int (*cmp)(const AVLNode *a, const AVLNode *b));

// Remove `node` from the tree.
// Does NOT free node (intrusive). Fully detaches node for safe reuse/debug.
// Returns the (possibly new) root pointer.
AVLNode *avl_remove(AVLNode *root, AVLNode *node);

// 0-based in-order rank lookup using subtree counts.
// Requires count fields to be correct (maintained by avl_* operations).
// Returns NULL if rank is out of bounds.
AVLNode *avl_at_rank(AVLNode *root, int64_t rank);

// In-order traversal helpers.
// Returns the minimum (leftmost) node in the subtree rooted at `root`.
AVLNode *avl_min(AVLNode *root);

// Returns the in-order successor of `node`, or NULL if `node` is the max.
AVLNode *avl_next(AVLNode *node);

#endif