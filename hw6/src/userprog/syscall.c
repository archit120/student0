#include "userprog/syscall.h"
#include <stdio.h>
#include "lib/round.h"
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
syscall_exit (int status)
{
  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  thread_exit ();
}

/*
 * This does not check that the buffer consists of only mapped pages; it merely
 * checks the buffer exists entirely below PHYS_BASE.
 */
static void
validate_buffer_in_user_region (const void* buffer, size_t length)
{
  uintptr_t delta = PHYS_BASE - buffer;
  if (!is_user_vaddr (buffer) || length > delta)
    syscall_exit (-1);
}

/*
 * This does not check that the string consists of only mapped pages; it merely
 * checks the string exists entirely below PHYS_BASE.
 */
static void
validate_string_in_user_region (const char* string)
{
  uintptr_t delta = PHYS_BASE - (const void*) string;
  if (!is_user_vaddr (string) || strnlen (string, delta) == delta)
    syscall_exit (-1);
}


static int
syscall_open (const char* filename)
{
  struct thread* t = thread_current ();
  if (t->open_file != NULL)
    return -1;

  t->open_file = filesys_open (filename);
  if (t->open_file == NULL)
    return -1;

  return 2;
}

static int
syscall_write (int fd, void* buffer, unsigned size)
{
  struct thread* t = thread_current ();
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      return size;
    }
  else if (fd != 2 || t->open_file == NULL)
    return -1;

  return (int) file_write (t->open_file, buffer, size);
}

static int
syscall_read (int fd, void* buffer, unsigned size)
{
  struct thread* t = thread_current ();
  if (fd != 2 || t->open_file == NULL)
    return -1;

  return (int) file_read (t->open_file, buffer, size);
}

static void
syscall_close (int fd)
{
  struct thread* t = thread_current ();
  if (fd == 2 && t->open_file != NULL)
    {
      file_close (t->open_file);
      t->open_file = NULL;
    }
}

static void* syscall_sbrk(intptr_t increment) {
	// TODO: Homework 6, YOUR CODE HERE
  struct thread* t = thread_current ();
  
  if(increment==0)  return t->heap_brk;


  uintptr_t page_boundary = ROUND_UP((uintptr_t)t->heap_brk-1, PGSIZE); // allocated upto here (exclusive)
  if(pg_ofs(t->heap_brk-1) == 0)
    page_boundary += PGSIZE;

  uintptr_t page_boundary_alt = ROUND_DOWN((uintptr_t)t->heap_brk + increment - 1, PGSIZE); // need to allocate till here (inclusive)

  // printf("%p %p %p %p\n", page_boundary, page_boundary_alt, t->heap_brk-1, t->heap_brk+increment-1);
  if(page_boundary <= page_boundary_alt)
  {
    uintptr_t c_bound = page_boundary;
    while(c_bound <= page_boundary_alt)
    {
      void* page = palloc_get_page(PAL_USER | PAL_ZERO);
      // printf("installing page at %p\n", page_boundary);
      if(page == NULL)
        break;
      if(!pagedir_set_page (t->pagedir, c_bound, page, true))
        break;
      c_bound += PGSIZE;
    }

    if(c_bound<=page_boundary_alt) {
      c_bound -= PGSIZE;
      while (c_bound >= page_boundary)
      {
        // printf("installing page at %p\n", page_boundary);

        palloc_free_page(pagedir_get_page(t->pagedir, c_bound));
        pagedir_clear_page(t->pagedir, c_bound);
        c_bound -= PGSIZE;
      }

      return -1;
    }
  }
  else if(page_boundary >= page_boundary_alt + 2*PGSIZE) {
    uintptr_t c_bound = page_boundary - PGSIZE;
    while(c_bound - page_boundary_alt >= PGSIZE) {
      // printf("removing page at %p\n", c_bound);
      palloc_free_page(pagedir_get_page(t->pagedir, c_bound));
      pagedir_clear_page(t->pagedir, c_bound);
      c_bound -= PGSIZE;
    }
  }
  // printf("new brk: %p %d\n", t->heap_brk+increment, increment);
  t->heap_brk += increment;
  // printf("new brk: %p %d\n", t->heap_brk, increment);
  return (t->heap_brk-increment);

}


static void
syscall_handler (struct intr_frame *f)
{
  uint32_t* args = (uint32_t*) f->esp;
  struct thread* t = thread_current ();
  t->in_syscall = true;
  t->esp_user = f->esp;
  validate_buffer_in_user_region (args, sizeof(uint32_t));
  switch (args[0])
    {
    case SYS_EXIT:
      validate_buffer_in_user_region (&args[1], sizeof(uint32_t));
      syscall_exit ((int) args[1]);
      break;

    case SYS_OPEN:
      validate_buffer_in_user_region (&args[1], sizeof(uint32_t));
      validate_string_in_user_region ((char*) args[1]);
      f->eax = (uint32_t) syscall_open ((char*) args[1]);
      break;

    case SYS_WRITE:
      validate_buffer_in_user_region (&args[1], 3 * sizeof(uint32_t));
      validate_buffer_in_user_region ((void*) args[2], (unsigned) args[3]);
      f->eax = (uint32_t) syscall_write ((int) args[1], (void*) args[2], (unsigned) args[3]);
      break;

    case SYS_READ:
      validate_buffer_in_user_region (&args[1], 3 * sizeof(uint32_t));
      validate_buffer_in_user_region ((void*) args[2], (unsigned) args[3]);
      f->eax = (uint32_t) syscall_read ((int) args[1], (void*) args[2], (unsigned) args[3]);
      break;

    case SYS_CLOSE:
      validate_buffer_in_user_region (&args[1], sizeof(uint32_t));
      syscall_close ((int) args[1]);
      break;

    case SYS_SBRK:
      validate_buffer_in_user_region (&args[1], sizeof(uint32_t));
      f->eax = (uint32_t) syscall_sbrk ((intptr_t) args[1]);
      break;

    default:
      printf ("Unimplemented system call: %d\n", (int) args[0]);
      break;
    }

  t->in_syscall = false;
}
