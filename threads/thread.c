#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
// [project1-C]
#include "fixed_point.h"
#ifdef USERPROG
#include "userprog/process.h"


#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Running 상태에서 일시정지되어 잠든, blocked 된 process/thread를 넣어 두는 list
timer_asleep()에서 사용된다.*/
static struct list sleep_list; 

/* Idle thread. */
//어떤 프로세스에서도 실행되고 있지 않은 스레드
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

//////////// Project 1 ////////////

// [project1-A]
/* List of processes in THREAD_BLOCKED state, that is, processes
   that are sleeping.*/
static struct list sleep_list; 

// [project1-C]
/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* The system load average, estimates the average number of threads ready to run over the past minute.
   It is Exponentially Weighted Moving Average (EWMA) and system-wide range.
   It related with calculating in "decay" recent_cpu.
   
   * EWMA analyze data points over a specific time period, with more recent data points receiving greater weight. */
static int load_avg ;

// set defaults
#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0 
#define LOAD_AVG_DEFAULT 0

//static bool value_less (const struct list_elem *, const struct list_elem *,void *); // [project1-B]

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);



/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };



/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);
	list_init (&sleep_list); // [project1-A]

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();

	
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);

	// [project1-C]
	load_avg = LOAD_AVG_DEFAULT; //booting
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);

	// [project1-B]

	/* compare the priorities of the currently running thread and the newly inserted one. 
	Yield the CPU if the newly arriving thread has higher priority (pptx)*/
	thread_switch();

	return tid;
}

// [project1-B]
/* If the first thread of ready list's priority is higher than 
   priority of current running thread, the current thread 
   yield CPU to that thread. 
   
   Function for context switching [project1-B]*/
void 
thread_switch() {
	/*  If ready list is empty, the current thread is idle thread
	so that we don't need to switch thread. */
	if (list_empty(&ready_list)){ 
		return;
	}

	struct list_elem* e = list_front(&ready_list);
	struct thread* ready_front = list_entry(e, struct thread, elem);

	int new_priority = ready_front->priority; 
	int current_priority = thread_get_priority();

	if (new_priority > current_priority){
		//donate_priority();
		thread_yield();
	}
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();

}

void push_sleeping_list(struct thread* target){
	if (target != idle_thread)
	list_push_back(&sleep_list, &target->elem);
}

void pop_sleeping_list(struct thread* target){
	if(target!=idle_thread)
	list_push_front(&sleep_list, &target->elem);
}

void sleep_thread(struct thread* target, int64_t waiting_time){

	target->sleeping_time = waiting_time;
		printf("[2] CT's tick setting: %d\n", target->sleeping_time);

	thread_block();

	push_sleeping_list(target);
		printf("[3] blocked_thread status = %s\n", target->status);
	
	



}
// ///////////////////
// void adding_sleep_list(struct thread* target){
// 	list_push_back(&sleep_list, &target->elem);
// }
// ///////////////////

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);

	list_insert_ordered(&ready_list, &t->elem, cmp_thread_priority, NULL); // [project1-B]
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* make a thread sleep */
void 
sleep_thread (int64_t waiting_time) { //[project1-A]

	struct thread* current_thread = thread_current();
	current_thread->sleeping_time = waiting_time;
	list_push_back(&sleep_list, &current_thread->elem);
	thread_block();
}

/* wake up the thread which satisfies awaking conditions: 
	over the waiting time in itself.*/
void 
awake_thread (int64_t ticks) { //[project1-A]

	struct list_elem * p;

	for(p = list_begin(&sleep_list); p != list_end(&sleep_list);){

		struct thread* sleeped_thread = list_entry(p,struct thread,elem);

		if (sleeped_thread->sleeping_time <= ticks){
			//list_remove returns next elem in the list.
			p = list_remove(p);
			thread_unblock(sleeped_thread);
			continue;
			}
		p=list_next(p);
		}
}


/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		//list_push_back (&ready_list, &curr->elem);
		list_insert_ordered(&ready_list, &curr->elem, cmp_thread_priority, NULL); // [project1-B] 
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {

	struct thread* curr = thread_current ();
	// [ project1-B : Donation ]
	if(! thread_mlfqs) {
		if (curr->priority == curr->original_priority) {
		curr->priority = new_priority;
		curr->original_priority = new_priority;
		
		} else {
			curr->original_priority = new_priority;
		}

	}
	
	if(thread_mlfqs){
		curr->priority = new_priority;
	}
	
	thread_switch();

}
// [project1-C]
/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}
// [project1-C]
/* Sets the current thread's nice value to NICE. */
/* 1) Sets the current thread's nice value to new nice 
   2) recalculates the thread's priority based on the new value. 
   3) If the running thread no longer has the highest priority, yields. */
void
thread_set_nice (int nice UNUSED) {
	// interrupt off needed 

	struct thread* curr = thread_current();

	enum intr_level old_level;
	old_level = intr_disable ();

	curr->nice = nice;
	// calc_priority(curr);
	//thread_switch();

	thread_switch();

	intr_set_level (old_level);

}
// [project1-C]
/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	enum intr_level old_level;
	old_level = intr_disable ();

	int nice = thread_current()->nice;

	intr_set_level (old_level);

	return nice;
}
// [project1-C]
/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	// return mult_mixed(load_avg, 100);
	//return load_avg * 100;

	enum intr_level old_level;
	old_level = intr_disable ();


	int load_avg100 = mult_mixed(load_avg, 100);
	load_avg100 = fp_to_int(load_avg100);
	//int res = fp_to_int(load_avg100);

	intr_set_level (old_level);

	return load_avg100;
	

}
// [project1-C]
/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	struct thread* curr = thread_current();
	enum intr_level old_level;
	old_level = intr_disable ();
	

	int recent_cpu100 = mult_mixed(curr->recent_cpu, 100);
	recent_cpu100 = fp_to_int(recent_cpu100);

	intr_set_level (old_level);

	return recent_cpu100; 
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;


	//[ project1-B : Donation ]
	/* initialize donation list & origianl priority */
	list_init(&t->donations); 
	t->original_priority = priority; 
	t->wait_on_lock=NULL;
	//lock_init(&t->wait_on_lock);

	// [project1-C]
	t->nice = NICE_DEFAULT; 
	t->recent_cpu = RECENT_CPU_DEFAULT;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		// [project1-B]
		// run the thread with highest priority
		//list_sort (&ready_list, value_less, NULL);

		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
/* TODO : keyword의 마지막 그거로 구현 해야 함 */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}


////////////// Project 1 ///////////////

// [project1-B] 
/*  <list_less_func *> for sorting list*/
bool cmp_thread_priority (const struct  list_elem *a_, const struct list_elem *b_, void *aux UNUSED) {
	struct thread*  a = list_entry(a_, struct thread, elem);
	struct thread*  b = list_entry(b_, struct thread, elem);
	//printf("ap: %d , bp: %d\n", a->priority, b->priority);

	return a->priority > b->priority;
}

// [project1-C] 
void
calc_load_avg(void) {
	int cvted_59 = int_to_fp(59);
	int cvted_60 = int_to_fp(60);
	int cvted_1 = int_to_fp(1);
	
	int front_frac = div_fp(cvted_59, cvted_60);
	int back_frac = div_fp(cvted_1, cvted_60);

	int num_rdyths = list_size(&ready_list);

	if (thread_current() != idle_thread) {
		num_rdyths++; 
		//threads in executing at the time of update. (except idle thread)
	}


	int front = mult_fp(front_frac, load_avg);
	int back = mult_mixed(back_frac, num_rdyths);

	load_avg = add_fp(front, back);

}
/* calculate decay for recent_cpu
   decay = (2*load_average)/ (2*load_average + 1)
*/
int
calc_decay(void) {

	int load_avb2 = mult_mixed(2, load_avg);
	int first = load_avb2;
	int second = add_mixed(load_avb2, 1);

	return div_fp(first, second);

}
/* Increase the recent_cpu of the currently running process by 1 in every timer interrupt*/
// 함수로 빼지 않아도 될 것 같음
void
increase_recent_cpu(void) {

	struct thread* t = thread_current();
	
	/* If the last t from the ready list is idle thread, 
	it means searching the list is done.*/
	if (t == idle_thread) {
		 return;
	}
	
	int curr_recent_cpu = t->recent_cpu;
	int incresed_recent = add_mixed(curr_recent_cpu, 1);
	t->recent_cpu = incresed_recent;


	int forchecking;
}

/* Update a thread.
   Decay and adjust in every second
   Get thread as a param.

   recent_cpu = decay * recent_cpu + nice,
   */
void
update_recent_cpu(struct thread* t) {

	if (t == idle_thread) {
		return;
	}

	int decay = calc_decay();
	int this_recent_cpu = t->recent_cpu;
	int this_nice = t->nice; 
	//int this_recent_cpu = thread_get_recent_cpu();
	//int this_nice = thread_get_nice();

	int first = mult_fp(decay, this_recent_cpu);
	
	t->recent_cpu = add_mixed(first, this_nice);
}

/*
Update all thread.
*/
void
mlfqs_update_recent_cpu(void) {
	struct list_elem* e;
	//(1) ready list
	if (!(list_empty(&ready_list))) {
	//recalc threads in ready list 
		for (e=list_begin(&ready_list) ; e!= list_end(&ready_list); e=list_next(e)) {
			struct thread* t = list_entry(e, struct thread, elem);
			update_recent_cpu(t); //update
		}

		list_sort(&ready_list, cmp_thread_priority, NULL);
	}
	//(2) sleep list
	if (!(list_empty(&sleep_list))) {

		for(e=list_begin(&sleep_list); e!=list_end(&sleep_list); e=list_next(e)) {
			struct thread* t = list_entry(e, struct thread, elem);
			update_recent_cpu(t);
		}

		//list_sort (&sleep_list, cmp_thread_priority, NULL);
	}
	//(3) current list
	struct thread* curr = thread_current();
	update_recent_cpu(curr);//update
}


/*
Update by 4 ticks 
priority = PRI_MAX – (recent_cpu / 4) – (nice * 2) */
void
calc_priority(struct thread* t) {

	if (t == idle_thread) {
		return;
	}
	
	int this_recent_cpu = t->recent_cpu;
	int this_nice = t->nice; 

	// (recent_cpu / 4)
	int cnvted_4 = int_to_fp(4);
	int first = div_mixed(this_recent_cpu, cnvted_4);
	// (nice * 2)
	int second =mult_mixed(this_nice, 2);

	int cvted_minus_sums = mult_mixed(add_fp(first, second), -1);
	int cvted_primax = PRI_MAX * (-1);
	int recalced_priority = sub_mixed(cvted_minus_sums,cvted_primax);

	t->priority = recalced_priority;
}

/* 
For all threads, priority is recalculated once in every fourth clock tick 
priority = PRI_MAX – (recent_cpu / 4) – (nice * 2)
For all threads, priority is recalculated once in every fourth clock tick 
*/
void
mlfq_update_priority(void) {

	//struct thread* t;
	struct list_elem* e;

	//(1) ready list
	if (!(list_empty(&ready_list))) {
		for ( e = list_begin(&ready_list) ; e != list_end(&ready_list); e = list_next(e) ) {
		struct thread* t = list_entry(e, struct thread, elem);
		calc_priority(t);
		}
		list_sort(&ready_list, cmp_thread_priority, NULL);


	}
	//(2) sleep list
	if (!(list_empty(&sleep_list))) {
		for(e=list_begin(&sleep_list); e!=list_end(&sleep_list); e=list_next(e)) {
			struct thread* t = list_entry(e, struct thread, elem);
			calc_priority(t);
		}

		//list_sort (&sleep_list, cmp_thread_priority, NULL);
	}
	//(3) current thread
	struct thread* curr = thread_current();

	calc_priority(curr);
}
