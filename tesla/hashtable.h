#ifndef TESLA_HASHNODE_H
#define TESLA_HASHNODE_H

#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HASHNODE {
  struct HASHNODE *next;
  int32 elem;
  void *dat;
} hash_node;

typedef struct {
  hash_node **table;
  int32 table_size;
} hashtable;

typedef struct {
  hash_node *list;
} llist;

TESLA_ERR hashtable_alloc(hashtable *tbl, int32 size);
TESLA_ERR hashtable_insert(hashtable *tbl, int32 elm, void *dat);
bool hashtable_lookup(hashtable *tbl, int32 elm, void **obj);
int32 hashtable_hash(hashtable *tbl, int32 elm);
#define hashtable_delete(tbl, elm) hashtable_DELETE(tbl, elm, TRUE);
#define hashtable_remove(tbl, elm) hashtable_DELETE(tbl, elm, FALSE);
bool hashtable_DELETE(hashtable *tbl, int32 elm, bool free);
void hashtable_free(hashtable *tbl);

void hashnode_free(hash_node *);
#define hashnode_sfree(node) free(node);
void hashnode_multi_free(hash_node *);
hash_node *hashnode_add(hash_node *curr, hash_node *add);
#define hashnode_new() malloc(sizeof(hash_node))

#define llist_new() malloc(sizeof(llist))
#define llist_alloc(ls) ((ls)->list = NULL)
TESLA_ERR llist_add(llist *, void *);
#define llist_concat(dst, src)                                                 \
  hashnode_add((l1)->list, (l2)->list);                                        \
  (l2)->list = NULL;
void *llist_get(llist *);

#ifdef __cplusplus
}
#endif

#endif
