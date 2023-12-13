#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

/* Project2. User Programs */
void argument_stack (char **parse, int count, void **rsp);

int process_add_file(struct file *f);
struct file *process_get_file(int fd);
// parse: 프로그램 이름과 인자가 담긴 배열
// count: 인자의 개수
// rsp: 스택 포인터를 가리키는 주소 값

#endif /* userprog/process.h */
