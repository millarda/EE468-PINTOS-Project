#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  printf ("system call!\n");
  int callNum = 0;
  //TODO have callNum be set to proper value
  switch(callNum){
    //TODO have case statements be proper cases
    case 0://write
    {
      //TODO understand argument passing
      break;
    }
    case 1://wait
    {
      //code required for Project B
      //will need to be changed in future versions
      while(1);
      break;
    }

  }
  thread_exit ();
}
