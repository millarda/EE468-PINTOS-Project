#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include <string.h>
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "shutdown.h"

static void syscall_handler (struct intr_frame *);
void sys_exit (int);
int sys_exec (const char *cmdline);

struct lock filesys_lock;

void 
syscall_init (void) 
{
  lock_init(&filesys_lock);
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
  int * stack = f->esp;
  ASSERT( sizeof(syscall_number) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  // the stack organization can be seen in lib/user/syscall.c
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
  case SYS_EXEC:
    {
      // Validate the pointer to the first argument on the stack
      if(!is_valid_ptr(stack + 1))
        sys_exit(-1);

      // Validate the buffer that the first argument is pointing to, this is a pointer to the command line args
      // that include the filename and additional arguments for process execute
      if(!is_valid_ptr((void *)*(stack + 1)))
        sys_exit(-1);

      // pointers are valid, call sys_exec and save result to eax for the interrupt frame
      f->eax = sys_exec((const char *)*(stack + 1));
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


int sys_exec (const char *cmdline){
  char * cmdline_cp;
  char * ptr;
  char * file_name;
  struct file * f;
  int return_value;
  // copy command line to parse and obtain filename to open
  cmdline_cp = malloc(strlen(cmdline)+1);
  strlcpy(cmdline_cp, cmdline, strlen(cmdline)+1);
  file_name = strtok_r(cmdline_cp, " ", &ptr);


  // it is not safe to call into the file system code provided in "filesys" directory from multiple threads at once
  // your system call implementation must treat the file system code as a critical section
  // Don't forget the process_execute() also accesses files.
  // => Obtain lock for file system
  lock_acquire(&filesys_lock);

  // try and open file name
  f = filesys_open(file_name);

  // f will be null if file not found in file system
  if (f==NULL){
    // nothing to do here exec fails, release lock and return -1
    lock_release(&filesys_lock);
    return -1;
  } else {
    // file exists, we can close file and call our implemented process_execute() to run the executable
    // note that process_execute accesses filesystem so hold onto lock until it is complete
    file_close(f);
    return_value = process_execute(cmdline);
    lock_release(&filesys_lock);
    return return_value;
  }
}

void sys_halt(void) {
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

/* The kernel must be very careful about doing so, because the user can pass
 * a null pointer, a pointer to unmapped virtual memory, or a pointer to
 * kernel virtual address space (above PHYS_BASE). All of these types of
 * invalid pointers must be rejected without harm to the kernel or other
 * running processes, by terminating the offending process and freeing its
 * resources */
bool
is_valid_ptr(const void *user_ptr)
{
  struct thread *curr = thread_current();
  if(user_ptr != NULL && is_user_vaddr(user_ptr))
  {
    return (pagedir_get_page(curr->pagedir, user_ptr)) != NULL;
  }
  return false;
}