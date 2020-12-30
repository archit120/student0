/*
 * mm_alloc.c
 */

#include "mm_alloc.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

struct list_node;

struct list_node
{
  char free;
  size_t size;
  struct list_node* prev;
  struct list_node* next;
  __uint16_t magic;
};

#define MAGIC 0xAB12
#define IS_MEM(x) ((x)->magic == MAGIC)

static struct list_node root;

void init_root() {
  root.magic = MAGIC;
  root.size = 0;
  root.next = NULL;
  root.prev = NULL;
}

void split_node(struct list_node* iter, size_t sz)
{
  //printf("splitting node\n");
  struct list_node* pt2 = ((void*)iter + sizeof(struct list_node) + sz);
  pt2->prev = iter;
  pt2->next = iter->next;
  pt2->magic = MAGIC;
  pt2->size = iter->size - sizeof(struct list_node) - sz;
  pt2->free = 1;
  iter->size = sz;

  if(iter->next)
    iter->next->prev = pt2;
  iter->next = pt2;

}

void dump_nodes()
{
  struct list_node* iter = &root;
  //printf("\n");
  while(iter != NULL)
  {
    assert(IS_MEM(iter));
    // printf("sz:%d cur:%x next:%x prev:%x free:%d\n", iter->size, iter, iter->next, iter->prev, iter->free);
    iter = iter->next;
  }
  //printf("\n");

}

void* clear_mem(void* ptr, size_t sz)
{
  memset(ptr + sizeof(struct list_node), 0, sz);
  return ptr + sizeof(struct list_node);
}
void* mm_malloc(size_t size)
{
  if(root.magic != MAGIC)
    init_root();
  if(size == 0)
    return NULL;

  struct list_node* iter = &root;
  //printf("mallocing\n");
  while(1) {
    //printf("sz:%d next:%x prev:%x free:%d\n", iter->size, iter->next, iter->prev, iter->free);

    if(iter->free && iter->size >= size) {
      if(iter->size > size+sizeof(struct list_node))
        split_node(iter, size);

      iter->free = 0;

      dump_nodes();
      return clear_mem(iter, size);
    }
    if(iter->next == NULL)  break;
    iter = iter->next;
  }

  // we reached the end and no memory found
  //printf("calling sbrk\n");
  struct list_node* base = sbrk(0);
  if(sbrk(sizeof(struct list_node) + size) == -1)
    return NULL;
  base->next = NULL;
  base->magic = MAGIC;
  base->free = 0;
  base->prev = iter;
  base->size = size;
  iter->next = base;
  return clear_mem(base, size);
}

size_t min(size_t x, size_t y)
{
  return x > y ? y : x;
}

void* mm_realloc(void* ptr, size_t size)
{
  if(size == 0 && ptr==NULL)  return NULL;
  if(size == 0){
    free(ptr);
    return NULL;
  }
  if(ptr == NULL) return mm_malloc(size);

  void* new_loc = mm_malloc(size);
  if(new_loc==NULL)
    return NULL;

  memcpy(new_loc, ptr, min(size, (((struct list_node*)ptr) - 1)->size));
  free(ptr);
  return NULL;
}

void collapse_any()
{
  struct list_node* iter = (&root)->next;
  //printf("Looking to collapse\n");
  while(iter != NULL)
  {
    assert(IS_MEM(iter));
    //printf("sz:%d cur:%x next:%x prev:%x free:%d\n", iter->size, iter, iter->next, iter->prev, iter->free);
    if(iter->free && iter->prev->free)
    {
      struct list_node* coal = iter->prev;
      coal->size += sizeof(struct list_node) + iter->size;
      coal->next = iter->next;
      if(iter->next)
        iter->next->prev = coal;
      
      //printf("collapsed!\n");
    }
    iter = iter->next;
  }
}

void mm_free(void* ptr)
{
  if(ptr == NULL) return;

  //printf("freeing\n");
  struct list_node* meta = ((struct list_node*)ptr) - 1;
  assert(IS_MEM(meta));
  assert(!meta->free);
  meta->free = 1;
  collapse_any();

  dump_nodes();
}
