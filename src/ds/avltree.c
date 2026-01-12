// avltree.c
//
// Intrusive AVL implementation.
//
// Key invariants maintained by all public operations:
// - Parent pointers remain consistent.
// - height/count metadata is updated via avl_recalc() and rebalance().
// - AVL balance factor stays within [-1, 1] after avl_fix_up().
//
// Comparator contract (avl_insert):
// - cmp(a,b) < 0 means a is ordered before b.
// - cmp(a,b) == 0 is treated as "go right" (duplicates permitted, but ordering is
//   comparator-defined).
#include "avltree.h"

static inline uint32_t u32_max(uint32_t a, uint32_t b) { return a > b ? a : b; }

// Recompute cached metadata from children.
// Must be called after any pointer mutation of n->left/n->right.
void avl_recalc(AVLNode *n) {
    if (!n) return;
    n->height = u32_max(avl_height(n->left), avl_height(n->right)) + 1;
    n->count = avl_count(n->left) + avl_count(n->right) + 1;
}

static inline int balance_factor(const AVLNode *n) {
    return (int)avl_height(n->left) - (int)avl_height(n->right);
}

// Replace parent's child pointer without touching newc->parent.
// Used by rotations/transplant; caller is responsible for fixing parent links.
static void replace_child(AVLNode *parent, AVLNode *oldc, AVLNode *newc) {
    if (!parent) return;
    if (parent->left == oldc) parent->left = newc;
    else if (parent->right == oldc) parent->right = newc;
}

/*
    Left rotation around x:

       x                 y
        \               / \
         y     ==>     x   ...
        /               \
       b                 b

    Preserves in-order sequence; updates parent pointers and metadata for x,y. 
*/
static AVLNode *rotate_left(AVLNode *x) {
    AVLNode *y = x->right;
    AVLNode *b = y->left;

    y->parent = x->parent;
    replace_child(x->parent, x, y);

    y->left = x;
    x->parent = y;

    x->right = b;
    if (b) b->parent = x;

    avl_recalc(x);
    avl_recalc(y);
    return y;
}

// Right rotation around y (mirror of rotate_left).
// Preserves in-order sequence; updates parent pointers and metadata for y,x.
static AVLNode *rotate_right(AVLNode *y) {
    AVLNode *x = y->left;
    AVLNode *b = x->right;

    x->parent = y->parent;
    replace_child(y->parent, y, x);

    x->right = y;
    y->parent = x;

    y->left = b;
    if (b) b->parent = y;

    avl_recalc(y);
    avl_recalc(x);
    return x;
}

// Rebalance a single node after metadata recomputation.
// Handles LL/LR/RR/RL cases and returns the new subtree root.
static AVLNode *rebalance(AVLNode *n) {
    avl_recalc(n);
    int bf = balance_factor(n);

    if (bf > 1) {
        // left heavy
        if (balance_factor(n->left) < 0) {
            // LR case
            rotate_left(n->left);
        }
        return rotate_right(n);
    }
    if (bf < -1) {
        // right heavy
        if (balance_factor(n->right) > 0) {
            // RL case
            rotate_right(n->right);
        }
        return rotate_left(n);
    }
    return n;
}

// Walk upward from `n`, rebalancing each ancestor.
// Returns the true tree root after all rotations.
//
// Important: rotations may change the local subtree root; we follow parent pointers
// to continue fixing upwards.
AVLNode *avl_fix_up(AVLNode *n) {
    if (!n) return NULL;

    AVLNode *cur = n;
    AVLNode *root = NULL;

    while (cur) {
        AVLNode *new_subroot = rebalance(cur);
        root = new_subroot;
        cur = new_subroot->parent;
    }

    // root now points at the topmost rebalanced subtree, which is the real root.
    while (root && root->parent) root = root->parent;
    return root;
}

// Insert node as a leaf then fix AVL invariants from its parent upwards.
//
// Notes:
// - This function calls avl_node_init(node): inserting a node resets its links/metadata.
// - If cmp(node,cur) >= 0, insertion proceeds into the right subtree (duplicates go right).
AVLNode *avl_insert(AVLNode *root, AVLNode *node,
                    int (*cmp)(const AVLNode *a, const AVLNode *b)) {
    avl_node_init(node);

    if (!root) return node;

    AVLNode *cur = root;
    AVLNode *parent = NULL;

    while (cur) {
        parent = cur;
        if (cmp(node, cur) < 0) cur = cur->left;
        else cur = cur->right;
    }

    node->parent = parent;
    if (cmp(node, parent) < 0) parent->left = node;
    else parent->right = node;

    return avl_fix_up(parent);
}

static AVLNode *subtree_min(AVLNode *n) {
    while (n && n->left) n = n->left;
    return n;
}

AVLNode *avl_min(AVLNode *root) {
    return subtree_min(root);
}

// In-order successor:
// - if right subtree exists: successor is min(right)
// - else: walk up until we traverse from a left child
AVLNode *avl_next(AVLNode *node) {
    if (!node) return NULL;

    // If there's a right subtree, successor is its minimum.
    if (node->right) return subtree_min(node->right);

    // Otherwise go up until we come from a left child.
    AVLNode *cur = node;
    AVLNode *p = cur->parent;
    while (p && p->right == cur) {
        cur = p;
        p = p->parent;
    }
    return p;
}

// Replace subtree rooted at u with subtree rooted at v.
// Updates root pointer if u was root, and maintains v->parent linkage.
static void transplant(AVLNode **root, AVLNode *u, AVLNode *v) {
    if (!u->parent) *root = v;
    else replace_child(u->parent, u, v);
    if (v) v->parent = u->parent;
}

// Remove node from tree (BST delete) and then restore AVL invariants.
//
// Strategy:
// - 0/1 child: transplant child into node's position.
// - 2 children: swap in-order successor `s` into node's position, then fix from the
//   successor's original parent (where height/count may have changed).
//
// Postcondition:
// - The removed node is fully detached (left/right/parent NULL, height=count=1)
//   so it can be safely reused or freed by the caller.
AVLNode *avl_remove(AVLNode *root, AVLNode *node) {
    if (!node) return root;
    
    // fix_from is the first ancestor whose subtree metadata may have changed.
    AVLNode *fix_from = node->parent;

    if (!node->left) {
        transplant(&root, node, node->right);
        fix_from = node->parent; // unchanged
    } else if (!node->right) {
        transplant(&root, node, node->left);
        fix_from = node->parent;
    } else {
        AVLNode *s = subtree_min(node->right); // successor
        if (s->parent != node) {
            // detach successor from its position
            AVLNode *s_parent = s->parent;
            transplant(&root, s, s->right);
            // successor takes node->right
            s->right = node->right;
            s->right->parent = s;
            fix_from = s_parent;
        } else {
            // successor is direct right child
            fix_from = s;
        }

        // successor takes node's place
        transplant(&root, node, s);
        s->left = node->left;
        s->left->parent = s;
    }

    // fully detach removed node (safer for reuse/debug)
    node->left = node->right = node->parent = NULL;
    node->height = 1;
    node->count = 1;

    if (fix_from) return avl_fix_up(fix_from);
    return root;
}

// Select the node with given 0-based in-order rank using subtree counts.
// Runs in O(height) assuming count fields are correct.
AVLNode *avl_at_rank(AVLNode *root, int64_t rank) {
    while (root) {
        uint32_t left_count = avl_count(root->left);

        if (rank < (int64_t)left_count) {
            root = root->left;
        } else if (rank == (int64_t)left_count) {
            return root;
        } else {
            rank -= (int64_t)left_count + 1;
            root = root->right;
        }
    }
    return NULL;
}
