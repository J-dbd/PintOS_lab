#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

//선언
void halt (void);
void exit (int status);
//pid_t fork (const char *thread_name);
int exec (const char *cmd_line);
//int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	printf ("system call!\n");
	

	int syscall_num = f->R.rax;

	switch (syscall_num) {
		case (SYS_HALT):
			halt();
			break;
		
		case (SYS_EXIT) :
			exit(f->R.rdi);
			break;
		
		case (SYS_FORK) :
			break;
		case (SYS_EXEC) :
			break;
		case (SYS_WAIT) :
			break;
		case (SYS_CREATE) :
			break;
		case (SYS_REMOVE) :
			break;
		case (SYS_OPEN) :
			break;
		case (SYS_FILESIZE) :
			break;
		case (SYS_READ) :
			break;
		case (SYS_WRITE) :
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case (SYS_SEEK) :
			break;
		case (SYS_TELL) :
			break;
		case (SYS_CLOSE) :
			break;

		default:
			exit(-1);
			thread_exit ();
	}
}




void check_address (void* addr) {
	/* A null pointer / A pointer to unmapped virtual memory */

	/* A pointer to kernel virtual memory address space (above USER_STACK) */

	//Lock or allocate the page only after verifying the validity of pointers 
	//enum intr_level old_level;
	//old_level = intr_disable ();

	if ((is_user_vaddr(addr) == false)) {
		//intr_set_level (old_level);
		exit(-1);
	}

	//intr_set_level (old_level);
	return;
}

void get_argument (struct intr_frame *if_) {
	int argc = if_->R.rdi;
	
}



void
halt (void) {
	power_off();
}

void
exit(int status) {
//thread == process
	struct thread* curr = thread_current();

	if (list_empty(&curr->child_list)) {
		curr->exit_status = status;
	}
	else {
		curr->exit_status = list_entry(list_front(&curr->child_list), struct thread, child_elem)->exit_status;
	}
	/* save exit status at process descriptor */
	printf("process %s : exit(%d)\n",curr->name, status);
	thread_exit();
}

int write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	if (fd == 1) {
		putbuf(buffer, size);
	}
	else {

		//file_write(, buffer, size);
	}

	return 0;


}