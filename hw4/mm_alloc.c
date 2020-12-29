/*
 * mm_alloc.c
 */

#include "mm_alloc.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

struct list_node;

struct list_node
{
  int free;
  int size;
  struct list_node* prev;
  struct list_node* next;
  int magic;
};

#define MAGIC 0xAB12C
#define IS_MEM(x) (x->magic == MAGIC)

static struct list_node root;

void init_root() {
  root.magic = MAGIC;
  root.size = 0;
  root.next = NULL;
  root.prev = NULL;
}

void split_node(struct list_node* iter, int sz)
{
  struct list_node* pt2 = ((void*)iter + sizeof(struct list_node) + sz);
  pt2->prev = iter;
  pt2->next = iter->next;
  pt2->magic = MAGIC;
  pt2->size = iter->size - sizeof(struct list_node) - sz;
  pt2->free = 1;
  iter->size = sz;
  iter->next = pt2;
}

void* mm_malloc(size_t size)
{
  if(!root.magic == MAGIC)
    init_root();
  
  struct list_node* iter = &root;
  while(1) {
    if(iter->free && iter->size >= size) {
      if(iter->size > size+sizeof(struct list_node))
        split_node(iter, size);

      iter->free = 0;
      return (void*)iter + sizeof(struct list_node);
    }
    if(iter->next == NULL)  break;
    iter = iter->next;
  }

  // we reached the end and no memory found

  struct list_node* base = sbrk(0);
  sbrk(sizeof(struct list_node) + size);
  base->next = NULL;
  base->magic = MAGIC;
  base->free = 0;
  base->prev = iter;
  base->size = size;
  return (void*)base + sizeof(struct list_node);
}

void* mm_realloc(void* ptr, size_t size)
{
  //TODO: Implement realloc

  return NULL;
}

void mm_free(void* ptr)
{
  //TODO: Implement free

  return NULL;
}
