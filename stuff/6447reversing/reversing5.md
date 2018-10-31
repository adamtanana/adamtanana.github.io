```c
typedef struct _tree {
    struct _tree* left;
    struct _tree* right;
} *Tree;

int count_size(Tree tree) {
    if (tree == NULL) 
        return 0;

    int count = 0;
    if (tree->left != NULL) 
        count += count_size(tree->left);

    if (tree->right != NULL) 
        count += count_size(tree->right);
    
    return count;
}
```
