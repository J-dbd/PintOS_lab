#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"
///// project 2/////
/* Use global lock to avoid race condition on file, */
struct lock filesys_lock;

void syscall_init (void);

//void syscall_close(int fd);

//void syscall_exit(int status);
#endif /* userprog/syscall.h */
