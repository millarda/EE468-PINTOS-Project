#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

static void syscall_handler (struct intr_frame *);
void sys_exit (int);
void prep_pages(const void *buffer, size_t size);
void unprep_pages(const void *buffer, size_t size);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) {
  if (lock_held_by_current_thread(&filesys_lock))
    lock_release (&filesys_lock);

  sys_exit (-1);
  NOT_REACHED();
}
static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;
  ASSERT( sizeof(syscall_number) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  memread_user(f->esp, &syscall_number, sizeof(syscall_number));
  _DEBUG_PRINTF ("[DEBUG] system call, number = %d!\n", syscall_number);

  // Store the esp, which is needed in the page fault handler.
  // refer to exception.c:page_fault() (see manual 4.3.3)
  thread_current()->current_esp = f->esp;

  // Dispatch w.r.t system call number
  // SYS_*** constants are defined in syscall-nr.h
  switch (syscall_number) {
  case SYS_HALT: // 0
    {
      sys_halt();
      NOT_REACHED();
      break;
    }

  case SYS_EXIT: // 1
    {
      int exitcode;
      memread_user(f->esp + 4, &exitcode, sizeof(exitcode));

      sys_exit(exitcode);
      NOT_REACHED();
      break;
    }

  case SYS_WAIT:
    {
      pid_t pid;
      memread_user(f->esp + 4, &pid, sizeof(pid_t));
      int ret = process_wait(pid);
      f->eax = (uint32_t) ret;
      break;
    }

  case SYS_TELL:
    {
      int fd;
      unsigned ret;

      memread_user(f->esp + 4, &fd, sizeof(fd));

      return_code = sys_tell(fd);
      lock_acquire (&filesys_lock);
      struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

      if(file_d && file_d->file) {
        ret = file_tell(file_d->file);
      }
      else
        ret = -1;

      lock_release (&filesys_lock);
      f->eax = (uint32_t) ret;
      break;
    }
  case SYS_REMOVE:
    {
      const char* filename;
      bool ret;

      memread_user(f->esp + 4, &filename, sizeof(filename));
      check_user((const uint8_t*) filename);
      lock_acquire (&filesys_lock);
      ret_code = filesys_remove(filename);
      lock_release (&filesys_lock);

      f->eax = ret;
      break;
    }
  case SYS_WRITE:
    {
      int fd, ret;
      const void *buffer;
      unsigned size;

      memread_user(f->esp + 4, &fd, sizeof(fd));
      memread_user(f->esp + 8, &buffer, sizeof(buffer));
      memread_user(f->esp + 12, &size, sizeof(size));
      ret = sys_write(fd, buffer, size);

      f->eax = (uint32_t) ret;
      break;
    }

  /* unhandled case */
  default:
    printf("[ERROR] system call %d is unimplemented!\n", syscall_number);

    // ensure that waiting (parent) process should wake up and terminate.
    sys_exit(-1);
    break;
  }
}

oid sys_halt(void) {
  shutdown_power_off();
}

void sys_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);

  // The process exits.
  // wake up the parent process (if it was sleeping) using semaphore,
  // and pass the return code.
  struct process_control_block *pcb = thread_current()->pcb;
  if(pcb != NULL) {
    pcb->exitcode = status;
  }
  else {
    // pcb == NULL probably means that previously
    // page allocation has failed in process_execute()
  }
  thread_exit();
}


//Checks if a ptr is null, to unmapped virtual memory or to the kernel
bool is_valid_ptr(const void *user_ptr)
{
  struct thread *curr = thread_current();
  if(user_ptr != NULL && is_user_vaddr (user_ptr))
  {
    return (pagedir_get_page(curr->pagedir, user_ptr)) != NULL;
  }
  return false;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  lock_acquire (&filesys_lock);
  int return_value;

  if(fd == 1) { // for stdout
    putbuf(buffer, size);
    return_value = size;
  }
  else {
    // for file
    struct file_desc* fd_buf = find_file_desc(thread_current(), fd, FD_FILE);

    if(fd_buf && fd_buf->file) {
      return_value = file_write(fd_buf->file, buffer, size);
    }
    else // no such file or can't open
      return_value = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}



static void
check_user (const uint8_t *uaddr) {

  if(get_user (uaddr) == -1)
    fail_invalid_access();
}
