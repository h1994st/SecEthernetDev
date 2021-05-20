#include "hashtable.h"
#include <string.h>
#include <stdlib.h>

#define RET_NULL(a) if(a == NULL) return TESLA_ERR_NO_MEMORY

/*int main(void){
  hashtable tbl;
  void *dat;
  void *obj;
  void *dat2;
  hashtable_alloc(&tbl,1000);
  dat="Hello!";
  dat2="Goodbye!";
  printf("%s\n",dat);
  hashtable_insert(&tbl,14,dat);
  hashtable_insert(&tbl,1014,dat2);
  hashtable_lookup(&tbl,14,&obj);
  printf("%s\n",obj);
  hashtable_lookup(&tbl,1014,&obj);
  printf("%s\n",obj);
  hashtable_delete(&tbl,14);
  hashtable_delete(&tbl,1014);
  hashtable_free(&tbl);
  }*/

int32 hashtable_hash(hashtable *tbl, int32 elm) {
  return elm % tbl->table_size;
}

TESLA_ERR hashtable_alloc(hashtable *tbl, int32 size) {
  tbl->table_size = size;

  tbl->table = malloc(sizeof(hash_node *) * size);
  RET_NULL(tbl->table);

  memset(tbl->table, 0, sizeof(hash_node *) * size);

  return TESLA_OK;
}

void hashtable_free(hashtable *tbl) {
  int32 i;
  if (tbl == NULL) return;

  for (i = 0; i < tbl->table_size; i++)
    if (tbl->table[i] != NULL)
      hashnode_multi_free(tbl->table[i]);

  free(tbl->table);
  free(tbl);
}

TESLA_ERR hashtable_insert(hashtable *tbl, int32 elm, void *obj) {
  int32 pos = hashtable_hash(tbl, elm);
  hash_node *node = NULL;

  node = hashnode_new();
  RET_NULL(node);

  node->dat = obj;
  node->elem = elm;
  node->next = NULL;

  //keep list in numerical order
  if (tbl->table[pos] == NULL || elm < tbl->table[pos]->elem)
    tbl->table[pos] = hashnode_add(tbl->table[pos], node);
  else {
    //not at the head, search for it
    hash_node *curr = tbl->table[pos];
    while (curr->next != NULL && elm > curr->next->elem)
      curr = curr->next;

    if (curr->elem == elm) {
      curr->dat = obj;
      free(node);
    } else {
      curr->next = hashnode_add(curr->next, node);
    }
  }
  return TESLA_OK;
}

void hashnode_free(hash_node *node) {
  free(node->dat);
  free(node);
}

void hashnode_multi_free(hash_node *node) {
  if (node->next != NULL)
    hashnode_multi_free(node->next);

  free(node->dat);
  free(node);
}

hash_node *hashnode_add(hash_node *curr, hash_node *add) {
  (add)->next = (curr);
  return (add);
}

//Remove an entry from the hashtable
//free=1 means delete the object in the table
//free=0 means don't delete the object in the table
bool hashtable_DELETE(hashtable *tbl, int32 elm, bool fr) {
  int32 pos = hashtable_hash(tbl, elm);

  hash_node *prev = tbl->table[pos];
  hash_node *curr = prev;

  if (curr != NULL && curr->elem == elm) {
    tbl->table[pos] = curr->next;
    if (fr) hashnode_free(curr);
    else free(curr);
    return TRUE;
  }

  while (curr != NULL && curr->next != NULL) {
    prev = curr;
    curr = curr->next;
    if (curr->elem == elm) {
      prev->next = curr->next;
      if (fr) hashnode_free(curr);
      else free(curr);
      return TRUE;
    }
  }

  return FALSE;
}

bool hashtable_lookup(hashtable *tbl, int32 elm, void **obj) {
  int32 pos = hashtable_hash(tbl, elm);

  hash_node *curr = tbl->table[pos];
  while (curr != NULL && curr->elem != elm)
    curr = curr->next;

  if (curr == NULL)
    return FALSE;
  else {
    *obj = curr->dat;
    return TRUE;
  }
}

TESLA_ERR llist_add(llist *list, void *dat) {
  hash_node *node = hashnode_new();
  RET_NULL(node);
  node->dat = dat;
  list->list = hashnode_add(list->list, node);
  return TESLA_OK;
}

void *llist_get(llist *l) {
  hash_node *ret = l->list;
  void *dat;
  if (ret == NULL) return NULL;

  dat = ret->dat;
  l->list = ret->next;
  free(ret);
  return dat;
}

void llist_move(llist *dst, llist *b) {
  hash_node *curr = NULL;
  while (b->list != NULL) {
    curr = b->list->next;
    b->list->next = dst->list;
    dst->list = b->list;
    b->list = curr;
  }
}
