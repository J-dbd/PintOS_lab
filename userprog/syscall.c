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

//// Project 2 //////
// for filesystem related
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "userprog/process.h"

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
void syscall_exit (int status);


void
syscall_init (void) {
	/// project 2 ///
	/* Initialize the lock */
	lock_init(&filesys_lock);
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	
}


void check_address (void* addr) {
	/* A null pointer / A pointer to unmapped virtual memory */
	struct thread *curr = thread_current();

	// if ((is_user_vaddr(addr) == false) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL) {
	// 	//intr_set_level (old_level);
	// 	syscall_exit(-1);
	// }


	if ((is_user_vaddr(addr) == false) || addr == NULL) {
		//intr_set_level (old_level);
		syscall_exit(-1);
	}
	
	// if (pml4_get_page(curr->pml4, addr) == NULL) {
	// 	syscall_exit(-1);
	// }
	// page fault를 직접 수정 함
		
	// //intr_set_level (old_level);
	// return;

}

///////////////////////////////////
////// Process Related Codes //////
///////////////////////////////////

void
syscall_halt (void) {
	power_off();
}

void
syscall_exit(int status) {
//thread == process
	struct thread* curr = thread_current();
	// 자식이 없을 때
	// if (list_empty(&curr->child_list)) {
	// 	curr->exit_status = status;
	// }
	// else { //자식이 하나라도 있을 때
	// 	curr->exit_status = list_entry(list_front(&curr->child_list), struct thread, child_elem)->exit_status;
	// }


	curr->exit_status = status;
	/* save exit status at process descriptor */
	printf("%s: exit(%d)\n",curr->name, status);


	thread_exit();
}

/* Change current process to the executable whose name is given in cmd_line, passing any given arguments. This never returns if successful. Otherwise the process terminates with exit state -1, if the program cannot load or run for any reason.  Please note that file descriptors remain open across an exec call. */
int syscall_exec(const char* file) {
	//printf("여기? 0 \n");

	/* This function does not change the name of the thread that called exec. */
	//copy the file name by palloc
	// char* fn_cpy = palloc_get_page (0);
	// if (fn_cpy == NULL) {
	// 	//printf("여기? 1 \n");
	// 	syscall_exit(-1);
	// 	//return -1;
	// }
	// memcpy(fn_cpy, file, PGSIZE);

	/* This never returns if successful. 
	Otherwise the process terminates with exit state -1 */

	if( process_exec(file) == -1) { //if failed
		//printf("여기? 2 \n");
		syscall_exit(-1);
		//return -1;
	}

}

int
syscall_fork (const char *thread_name, struct intr_frame* if_) {
	//////// type 1

	// struct thread* curr = thread_current();
	// memcpy(&curr->parent_if, if_, sizeof(struct intr_frame));
	// int child_pid;
	// if((child_pid = process_fork(thread_name, if_)) < 0) {
	// 	//if fork is failed
	// 	return -1;
	// }
	// struct thread* child = get_child_thread(child_pid);
	// sema_down(&child->load_sema);
	// ////sema_down(&curr->load_sema);
	// return child_pid;

	/////type 1 end

	///////////////// type2
	return process_fork(thread_name, if_); 
	//////////////// type2 end
}

int
syscall_wait(int pid) {
	return process_wait(pid);
}


//////////////////////////////////////
////// FileSystem Related Codes //////
//////////////////////////////////////

/* Protect filesystem related code by global lock. */
bool 
syscall_create(const char* file, unsigned initial_size) {
	check_address(file); // null and bad ptr together ... but bad ptr (X)
	check_address(file + initial_size - 1);

	int success = filesys_create(file, initial_size);

	if (success) {
		lock_acquire(&filesys_lock);
		struct thread* curr = thread_current();
		struct file** curr_fdt = curr->fdt;
		int fd;
		for (fd = 2; fd < 64; fd++) {
			if(curr_fdt[fd] == NULL) {
				curr_fdt[fd] = file;
				break;
			}
		}
		curr->next_fd += 1;
		lock_release(&filesys_lock);
		return true;
	}
	else {
		return false;
	}
}

/* File is removed regardless of whether it is open or closed. */
bool 
syscall_remove(const char* file) {
	int success = filesys_remove(file);

	if (success) {
		lock_acquire(&filesys_lock);
		struct thread* curr = thread_current();
		struct file** curr_fdt = curr->fdt;
		int fd;
		for (fd = 2; fd < 64; fd++) {
			if(curr_fdt[fd] == file) {
				curr_fdt[fd] = NULL;
				break;
			}
		}
		curr->next_fd -=1;
		lock_release(&filesys_lock);
		return true;
	}
	else {
		return false;
	}
}

// 자식 프로세스의 상속 관련해서 체크가 필요해 보임
int 
syscall_open (const char *file) {
	//check_address(file);
	struct file* opened_file = filesys_open(file);
	//file_open 은 *file과 inode가 필요하다! 
	// struct file 에서 어떻게 fd를 추출해 낼 것인가?

	if (opened_file == NULL) {
		return -1;//checking
	}
	lock_acquire(&filesys_lock);
	struct thread* curr = thread_current();
	struct file** curr_fdt = curr->fdt;

	// FD 0 and 1 are allocated for stdin and stdout, respectively.

	int fd;
	for (fd = 2; fd < 64; fd++) {
		if(curr_fdt[fd] == NULL) {
			curr_fdt[fd] = opened_file;
			break;
		}
	}

	if(fd == 64) {
		lock_release(&filesys_lock);
		file_close(opened_file);
		return -1;//checking
	}
	// Increment the next_fd for the next open file
	curr->next_fd = fd + 1; 
	// realease the lock
	lock_release(&filesys_lock);

	return fd;
}

int 
syscall_filesize(int fd) {

	lock_acquire(&filesys_lock);

	struct file* target_file = get_file_by_fd_from_curr_thread(fd);
	off_t filesize = file_length(target_file);

	lock_release(&filesys_lock);
	return (int)(filesize);
}

/* 
Read size bytes from the file open as fd into buffer.
Return the number of bytes actually read (0 at end of file), or -1 if fails
If fd is 0, it reads from keyboard using input_getc(), otherwise reads from file using file_read() function.


*/
int 
syscall_read(int fd, void *buffer, unsigned size) {

	check_address(buffer); //check buffer 
	// size는 어떻게 체크하지?
	lock_acquire(&filesys_lock);
	int byte_size = 0;
	// If fd is 0, it reads from keyboard using input_getc()
	if (fd == 0) { //keyboard input
		
		for (int i = 0; i< size; i++){
			uint8_t key = input_getc();
			((char*)buffer)[i] = key;
			byte_size++;

			if(key == '\n') {
				break;
			}
		}
	}
	else if (fd == 1) {
		//printf("fd == 1\n");
		lock_release(&filesys_lock);
		return -1;
	}
	else {
		//lock_acquire(&filesys_lock);
		struct file* target_file = get_file_by_fd_from_curr_thread(fd);

		if (target_file == NULL) {
			//만약 fd가 존재하지 않아 파일이 존재하지 않는다면 -1을 리턴 
			lock_release(&filesys_lock);
			return -1;
		}
		byte_size = file_read(target_file, buffer, size);
		//lock_release(&filesys_lock);
	}
	lock_release(&filesys_lock);
	return byte_size;
}

/* 
Writes size bytes from buffer to the open file fd.
Returns the number of bytes actually written.
If fd is 1, it writes to the console using putbuf(), 
otherwise write to the file using file_write() function

*/
int 
syscall_write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);//check buffer
	lock_acquire(&filesys_lock);
	int byte_size = 0;
	if (fd == 1) { 
		
		//STDOUT인 경우 버퍼에 쓰여진 내용을 그대로 화면에 출력 
		//쓰인 size를 저장
		putbuf(buffer, size);
		byte_size = size;
	}
	else if (fd == 0) {
		lock_release(&filesys_lock);
		return -1;
	}
	else {
		
		struct file* target_file = get_file_by_fd_from_curr_thread(fd);
		
		if (target_file==NULL) {
			//만약 fd가 존재하지 않아 파일이 존재하지 않다면 -1 리턴 시킨다.
			lock_release(&filesys_lock);
			return -1;
		}

		byte_size = file_write(target_file, buffer, size);
	}
	lock_release(&filesys_lock);
	return byte_size;
}

void
syscall_seek(int fd, unsigned position) {
	check_address(position);

	if (fd < 2){ //fd가 0이나 1일 경우 리턴 
		return -1;
	}

	lock_acquire(&filesys_lock);
	struct file* target_file = get_file_by_fd_from_curr_thread(fd);
	if (target_file==NULL) {
			//만약 fd가 존재하지 않아 파일이 존재하지 않다면 -1 리턴 시킨다.
			lock_release(&filesys_lock);
			return -1;
		}
	
	file_seek(target_file, position);
	lock_release(&filesys_lock);

}

/* Return the position of the next byte 
to be read or written in open file fd.
*/
unsigned 
syscall_tell (int fd) {

	unsigned int next_byte;
	
	if (fd < 2){//fd가 0이나 1일 경우 리턴 
		return -1;
	}

	lock_acquire(&filesys_lock);
	struct file* target_file = get_file_by_fd_from_curr_thread(fd);
	if (target_file==NULL) {
			//만약 fd가 존재하지 않아 파일이 존재하지 않다면 -1 리턴 시킨다.
			lock_release(&filesys_lock);
			return -1;
		}
	next_byte = file_tell(target_file);

	lock_release(&filesys_lock);
	return next_byte;
}
/* close() set 0 at file descriptor entry at index fd */
void
syscall_close(int fd) {

	if (fd < 2){//fd가 0이나 1일 경우 리턴 
		return -1;
	}

	lock_acquire(&filesys_lock);
	struct file* target_file = get_file_by_fd_from_curr_thread(fd);
	if (target_file==NULL) {
			//만약 fd가 존재하지 않아 파일이 존재하지 않다면 -1 리턴 시킨다.
			lock_release(&filesys_lock);
			//return -1;
			syscall_exit(-1);
			return;
		}
	
	file_close(target_file);
	//close() 시 File Descriptor 테이블에 해당 엔트리 값을 NULL로 초기화
	struct thread* curr = thread_current();
	struct file** curr_fdt = curr->fdt;
	curr_fdt[fd] = NULL; //Update File Descriptor Table
	curr->next_fd -= 1; // Update Next File Descriptor

	lock_release(&filesys_lock);
	return;

}
/////////////////////////////
///    syscall_handler   ///
////////////////////////////

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	//printf ("system call!\n");
	
	int syscall_num = f->R.rax;
	//check_address(f->R.rdi);

	switch (syscall_num) {
		case (SYS_HALT):
			syscall_halt();
			break;
		
		case (SYS_EXIT) :
			syscall_exit(f->R.rdi);
			break;
		
		case (SYS_FORK) :
			//check_address(f->R.rdi);
			syscall_fork(f->R.rdi, f);
			break;
		case (SYS_EXEC) :
			check_address(f->R.rdi);
			syscall_exec(f->R.rdi);
			//f->R.rax = syscall_exec(f->R.rdi);
			break;
		case (SYS_WAIT) :
			//check_address(f->R.rdi);
			f->R.rax = syscall_wait(f->R.rdi);
			break;
		case (SYS_CREATE) :
			//check_address(f->R.rdi);
			f->R.rax = syscall_create(f->R.rdi, f->R.rsi);
			break;
		case (SYS_REMOVE) :
			check_address(f->R.rdi);
			f->R.rax = syscall_remove(f->R.rdi);
			break;
		case (SYS_OPEN) :
			check_address(f->R.rdi);
			f->R.rax = syscall_open(f->R.rdi);
			break;
		case (SYS_FILESIZE) :
			check_address(f->R.rdi);
			f->R.rax =  syscall_filesize(f->R.rdi);
			break;
		case (SYS_READ) :
			check_address(f->R.rdi);
			f->R.rax =  syscall_read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case (SYS_WRITE) :
			check_address(f->R.rdi);
			f->R.rax = syscall_write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case (SYS_SEEK) :
			check_address(f->R.rdi);
			syscall_seek(f->R.rdi, f->R.rsi);
			break;
		case (SYS_TELL) :
			check_address(f->R.rdi);
			f->R.rax = syscall_tell(f->R.rdi);
			break;
		case (SYS_CLOSE) :
			check_address(f->R.rdi);
			syscall_close(f->R.rdi);
			break;

		default:
			syscall_exit(-1);
			//thread_exit ();
	}
}

