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
#include "lib/user/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include <string.h>
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
void sys_exit (int);
void sys_halt(void);
int sys_exec (const char *cmdline);

struct lock filesys_lock;

bool is_valid_ptr(const void *user_ptr);

struct file_descriptor * retrieve_file(int fd);

struct file_descriptor{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

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
  uint32_t *esp;
  //printf("SYSCALL: Entered syscall\n");

  // The system call number is in the 32-bit word at the caller's stack pointer.
  esp = f->esp;
  //printf("SYSCALL: esp is %d\n", *esp);
  if(!is_valid_ptr(esp)){
    //printf("SYSCALL: esp invalid pointer\n");
    sys_exit(-1);
  }
  // Dispatch w.r.t system call number
  // SYS_*** constants are defined in syscall-nr.h
  switch (*esp) {
  case SYS_HALT:
    {
      //printf("SYSCALL: SYS_HALT \n");
      sys_halt();
      break;
    }
  case SYS_EXIT:
    {
      //printf("SYSCALL: SYS_EXIT \n");
      //is_valid_ptr(esp+1);
      sys_exit(esp+1);
      break;
    }
  case SYS_WAIT:
    {
      if(is_valid_ptr((const void*) (esp+1))){//Make sure this check is appropriate
        f->eax = process_wait(*(esp + 1));//
      }else{
        sys_exit(-1);
      }
      break;
    }
    case SYS_CREATE:
    {
      if(!is_valid_ptr((const void*) (esp+5)))
        sys_exit(-1);

      if(!is_valid_ptr((const void*) (esp+4)))
        sys_exit(-1);

      if(!is_valid_ptr((const void*) *(esp+4)))
        sys_exit(-1);

      lock_acquire(&filesys_lock);
      f->eax = filesys_create(*(esp+4), *(esp+5));
      lock_release(&filesys_lock);

      break;
    }
  case SYS_REMOVE:
    {
      if(!is_valid_ptr((const void*) (esp+4)))
        sys_exit(-1);

      if(!is_valid_ptr((const void*) *(esp+4)))
        sys_exit(-1);

      lock_acquire(&filesys_lock);
      f->eax = filesys_remove(*(esp+1));
      lock_release(&filesys_lock);
      break;
    }
  case SYS_WRITE:
    {
      //printf("WRITE: starting syswrite with esp = %d\n", *esp);
      if(is_valid_ptr((const void*)(esp+5)) && is_valid_ptr( (const void*) (esp+6)) && is_valid_ptr((const void*)(esp+7)))
      {
        //printf("WRITE: size = %d\n", *(esp+7));
        if(is_valid_ptr((const void*)(*(esp+6))) && is_valid_ptr((const void*)((*(esp+6)+*(esp+7)-1))))
          f->eax = (uint32_t) sys_write((int) *(esp+5), (const void*) *(esp+6), (unsigned) *(esp+7));
        else{
          if(!is_valid_ptr((const void*)(*(esp+6)))){
            //printf("write: esp %x \n", (esp));
            //printf("write: esp + 6 %x \n", (esp + 6));
            //printf("write: *(esp + 6) hex %s \n", (char *)*(esp + 6));
            //printf("write: fd = *(esp + 5) %d \n", *(esp + 5));
            //printf("WRITE: *(esp + 6) invalid \n");
          }
          if(!is_valid_ptr((const void*)((*(esp+6)+*(esp+7)-1)))){
            //printf("WRITE: (*(esp+5)+*(esp+6)-1) invalid \n");
          }
          //printf("WRITE: Pointer found as invalid 2\n");
          sys_exit(-1);
        }
      }else{
        //printf("WRITE: Pointer found as invalid 1\n");
        sys_exit(-1);
      }
      break;
    }
  case SYS_EXEC:
    {
      // Validate the pointer to the first argument on the stack
      if(!is_valid_ptr((void*)(esp + 1)))
        sys_exit(-1);

      // Validate the buffer that the first argument is pointing to, this is a pointer to the command line args
      // that include the filename and additional arguments for process execute
      if(!is_valid_ptr((void *)*(esp + 1)))
        sys_exit(-1);

      // pointers are valid, call sys_exec and save result to eax for the interrupt frame
      f->eax = sys_exec((const char *)*(esp + 1));
      break;
    }
  /* unhandled case */
  default:
    printf("[ERROR] a system call is unimplemented!\n");

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
  int thread_id;
  //printf("SYSCALL: sys_exec: cmdline: %s \n", cmdline);
  // copy command line to parse and obtain filename to open
  cmdline_cp = malloc(strlen(cmdline)+1);
  strlcpy(cmdline_cp, cmdline, strlen(cmdline)+1);
  file_name = strtok_r(cmdline_cp, " ", &ptr);

  //printf("SYSCALL: sys_exec: file_name: %s \n", file_name);

  // it is not safe to call into the file system code provided in "filesys" directory from multiple threads at once
  // your system call implementation must treat the file system code as a critical section
  // Don't forget the process_execute() also accesses files.
  // => Obtain lock for file system
  lock_acquire(&filesys_lock);

  // try and open file name
  f = filesys_open(file_name);

  // f will be null if file not found in file system
  if (f == NULL){
    // nothing to do here exec fails, release lock and return -1
    //printf("SYSCALL: sys_exec: filesys_open failed\n");
    lock_release(&filesys_lock);
    return -1;
  } else {
    // file exists, we can close file and call our implemented process_execute() to run the executable
    file_close(f);
    lock_release(&filesys_lock);

    // wait for child process to load successfully, otherwise return -1
    thread_current()->child_load = 0;
    thread_id = process_execute(cmdline);
    lock_acquire(&thread_current()->child_lock);
    //printf("SYSCALL: sys_exec: waiting until child_load != 0\n");
    while(thread_current()->child_load == 0)
      cond_wait(&thread_current()->child_condition, &thread_current()->child_lock);
    //printf("SYSCALL: sys_exec: child_load != 0\n");
    if(thread_current()->child_load == -1) // load failed no process id to return
     {
       thread_id = -1;
       //printf("SYSCALL: sys_exec: child_load failed\n");
     }
    lock_release(&thread_current()->child_lock);
    return thread_id;
  }
}

void sys_halt(void) {
  shutdown_power_off();
}

void sys_exit(int status) {
  thread_exit();
  // TODO
}


/* The kernel must be very careful about doing so, because the user can pass
 * a null pointer, a pointer to unmapped virtual memory, or a pointer to
 * kernel virtual address space (above PHYS_BASE). All of these types of
 * invalid pointers must be rejected without harm to the kernel or other
 * running processes, by terminating the offending process and freeing its
 * resources */
bool is_valid_ptr(const void *user_ptr)
{
  struct thread *curr = thread_current();
  if(user_ptr != NULL && is_user_vaddr(user_ptr))
  {
    return (pagedir_get_page(curr->pagedir, user_ptr)) != NULL;
  }
  if(user_ptr == NULL){
    printf("Pointer is NULL\n");
  }else{
    printf("Pointer is not user address space\n");
  }
  return false;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  //printf("WRITE: fd = %d, size = %d\n", fd, size);
  struct file_descriptor *fd_struct;
  int bytes_written = 0;

  lock_acquire(&filesys_lock);

  if(fd == STDIN_FILENO){
    lock_release(&filesys_lock);
    return -1;
  }
  if(fd == STDOUT_FILENO){
    putbuf (buffer, size);
    lock_release(&filesys_lock);
    return size;
  }

  fd_struct = retrieve_file(fd);
  if(fd_struct != NULL){
    bytes_written = file_write(fd_struct->file_struct, buffer, size);
  }

  lock_release(&filesys_lock);
  return bytes_written;
}

struct file_descriptor * retrieve_file(int fd){
  struct list_elem *list_element;
  struct file_descriptor *fd_struct;
  for(list_element = list_head(&thread_current()->open_files); list_element != list_tail(&thread_current()->open_files);
  list_element = list_next(list_element)){
    fd_struct = list_entry (list_element, struct file_descriptor, elem);
    if (fd_struct->fd_num == fd)
      return fd_struct;
  }
  //This is done for the tail
  fd_struct = list_entry (list_element, struct file_descriptor, elem);
  if (fd_struct->fd_num == fd)
    return fd_struct;

  return NULL;
}
