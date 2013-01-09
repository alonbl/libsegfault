/*
 * Copyright (C) 2006 Jerome Glisse.
 *
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER(S) AND/OR ITS SUPPLIERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */
/*
 * Authors:
 *	Jerome Glisse <j.glisse@gmail.com>
 *	ported to x86_64 by Yaniv Pascal <yanivpas@gmail.com>
 */
/*
 * Greets fly to someone@segfault.net and phrack issue 58
 *
 * $ gcc -Wall -O2 -fPIC -DDEBUG -c segfault.c
 * $ ld -Bshareable -o libsegfault.so segfault.o -ldl
 * $ export SF_ADDR=0xDEADBEEF
 * $ LD_PRELOAD=./libsegfault.so Xorg &
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <strings.h>
#include <ucontext.h>
#include <udis86.h>

#define MAX_NUM_OF_MAPS 13

/* Debug stuff */
#ifdef DEBUG
#define DEBUGF(format, ...) \
	do { \
		fprintf(context.log, "%s[%d]", __FILE__, __LINE__); \
		fprintf(context.log, format, __VA_ARGS__); \
	} while(0)
#else
#define DEBUGF(format, ...)
#endif

#if defined(__i386__)
#define ADDR_TYPE uint32_t
#define CPU_MODE 32
#define CODE_BUFFER_SIZE 1042 /* FIXME: */ 
#define MAX_INST_SIZE 16 /* FIXME: discover the real value */
#define BREAKPOINT 0xcc
#define INST_PTR(context) ((context)->uc_mcontext.gregs[REG_EIP])
#elif defined(__x86_64)
#define ADDR_TYPE uint64_t
#define CPU_MODE 64 
#define CODE_BUFFER_SIZE 1042 /* FIXME: */
#define MAX_INST_SIZE 16 /* FIXME: discover the real value */
#define BREAKPOINT 0xcc /* FIXME: ???? */
#define INST_PTR(context) ((context)->uc_mcontext.gregs[REG_RIP])
#else
#error unsupported architecture
#endif

#define page_align(address)  (char*)((unsigned long)(address) & -(getpagesize()))

typedef struct {
	void *mmap_addr;
	void *addr;
	size_t size;
	unsigned long saddr;
	unsigned long eaddr;
} map_t;

/* Structure storing everythings we need to know */
typedef struct {
	ud_t disasm;
	int protected;
	FILE *log;
	ucontext_t *context;
	uint8_t *inst_addr;
	uint8_t inst_part;
	ADDR_TYPE *fault_addr;

    map_t maps[MAX_NUM_OF_MAPS];
    long map_count;

} segfault_t;

typedef enum error_e {
    SUCCESS = 0,
    ADDR_NOT_FOUND,
    TOO_MANY_MAPS,
    MPROTECT_FAILD
} error_t;
/*
 * o_signal is a ptr to original libc signal handler
 * o_mmap is a ptr to original libc mmap function
 * libc_handle
 */
static void* (* o_signal)(int, void(*)(int));
static void* (* o_sigaction)(int, struct sigaction*, struct sigaction*);
static void* (* o_mmap)(
	void *addr,
	size_t len,
	int prot,
	int flags,
	int fildes,
	off_t off
);

static void* libc_handle = NULL;


/*
 * static variables used for immediate value
 */
static segfault_t context;

/*
 * That's all folks in case of fatal error or unhandled instruction thus no
 * bad things happen.
 */
static void thats_all_folks(void)
{
	fprintf(context.log, "That's all folks !\n");
    exit(-1);
}

static error_t add_map(map_t **map)
{
    if (MAX_NUM_OF_MAPS <= context.map_count) {
        return TOO_MANY_MAPS;
    }

    context.map_count++;
    *map = &context.maps[context.map_count];

    return SUCCESS;
}

static error_t find_map(ADDR_TYPE addr, map_t **map)
{
    long i = 0;
    for (; i < MAX_NUM_OF_MAPS; i++) {
        if ((context.maps[i].saddr <= addr) &&
            (context.maps[i].eaddr >= addr)) {
            *map = &context.maps[i];
            return SUCCESS;
        }
    }
    return ADDR_NOT_FOUND;
}

/*
 * Protect memory
 */
static void protect(map_t *map)
{
	if (mprotect(map->addr, map->size, PROT_NONE) < 0) {
		fprintf(
			context.log,
			"mprotect(0x%08X|0x%08X) failed\n", 
			(unsigned int)map->addr,
			map->size
		);
		exit(1);
	}
}

/*
 * Unprotect memory
 */
static void unprotect(map_t *map)
{
	if (mprotect(map->addr, map->size, PROT_READ | PROT_WRITE) < 0) {
		fprintf(
			context.log,
			"mprotect(0x%08X|0x%08X) failed\n", 
			(unsigned int)map->addr,
			map->size
		);
		exit(1);
	}
}

/*
 * For library testing (or i am not root on my office computer ;))
 */
void libsegfault_protect(void* addr, size_t size, FILE* log)
{
    map_t *map = NULL;
    error_t status = SUCCESS;

    /* add another map to the maping list */
    status = add_map(&map);
    if (SUCCESS != status) {
        return; /* FIXME: add a status code return */
    }

	map->addr = addr;
	map->size = size;
	map->saddr = (unsigned long)map->addr;
	map->eaddr = (unsigned long)map->addr + map->size;
	context.log = log;
	protect(map);
	DEBUGF(
		"protecting 0x%08X of lenght 0x%08X)\n",
		(unsigned int)map->addr,
		map->size
	);
	DEBUGF(
		"protecting 0x%08lX up to 0x%08lX)\n",
		map->saddr,
		map->eaddr
	);
}

/*
 * Take over mmap
 */
void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
    map_t *map = NULL;
    error_t status = SUCCESS;

    /* add another map to the maping list */
    status = add_map(&map);
    if (SUCCESS != status) {
        thats_all_folks();
    }

	DEBUGF(
		"intercepting mmap(0x%08X, 0x%08X, %d, %d, %d, 0x%08lX)\n",
		(unsigned int)addr,
		len,
		prot,
		flags,
		fildes,
		off
	);
		map->size = len;
		map->addr = o_mmap(
			addr,
			len,
			PROT_NONE,
			flags,
			fildes,
			off
		);
		map->saddr = (unsigned long)map->addr;
		map->eaddr = (unsigned long)map->addr + map->size;
		printf("intercepting mmap initialize\n");
		DEBUGF(
			"mmap protecting  0x%08X of lenght 0x%08X)\n",
			(unsigned int)map->addr,
			map->size
		);
		DEBUGF(
			"protecting 0x%08lX up to 0x%08lX)\n",
			map->saddr,
			map->eaddr
		);
		return map->addr;
}

/*
 * Replace the libc sigaction function
 */
int sigaction(int sn,const struct sigaction *act, struct sigaction *oldact)
{
    if (SIGSEGV == sn) {
        return 0;
    }
    if (SIGTRAP == sn) {
        return 0;
    }

    return o_sigaction(sn, act, oldact);
}

/*
 * Replace the libc signal function
 */
void (*signal(int sn, void (*sighandler)(int)))()
{
	/* FIXME: check if we need to change this because of sigaction */
	if (sn == SIGSEGV) {
		/* return segfault_handler; */
		return NULL;
	}
	if (sn == SIGTRAP) {
		/* return segfault_handler; */
		return NULL;
	}

	/* in all other cases call the original libc signal() -function */
	return o_signal(sn, sighandler);
}

/* TODO: make a stub for sigaction also */


static error_t set_breakpoint(uint8_t *ptr)
{
	int result = 0;
    error_t status = SUCCESS;

	context.inst_addr = ptr;
	context.inst_part = *ptr;
	/* FIXME: change the premisstions back to the orginal */
	result = mprotect(
		(void*)(page_align((unsigned int)context.inst_addr)),
		getpagesize(),
		PROT_READ | PROT_WRITE | PROT_EXEC
	);
	if (result < 0) {
        status = MPROTECT_FAILD;
		fprintf(
			context.log,
			"set_breakpoint mprotect failed\n"
		);
		goto l_exit;
	}

	/* set the breakpoint opcode */
	*ptr = BREAKPOINT;

l_exit:
	return status;
}

/*
 * Process opcode which caused the segfault
 */
static int process_opcode(uint8_t* opcode)
{
	unsigned int size = 0;

	ud_set_input_buffer(&(context.disasm), opcode, MAX_INST_SIZE);
	size = ud_disassemble(&(context.disasm));
	fprintf(context.log,"\t%s\n", ud_insn_asm(&(context.disasm)));

	return size;
}


/* FIXME: can create starvetion? */
static void trap_handler(int sig, siginfo_t *info, void *signal_ucontext)
{
    map_t *map = NULL;
    error_t status = SUCCESS;

	/* TODO: check the si_code */
	if ((context.inst_addr+1) != (void*)INST_PTR((ucontext_t*)(signal_ucontext))) {
		return;
	}

    status = find_map(context.fault_addr, &map);
    if (SUCCESS != status) {
        thats_all_folks();
    }

	/* remove the breakpoint */
	*context.inst_addr = context.inst_part;
    INST_PTR((ucontext_t*)(signal_ucontext))--;
	fprintf(context.log, "value after : 0x%x\n", *context.fault_addr);
	protect(map);
}

/*
 * All the segfault handling fun happen here
 */
static void segfault_handler(int sig, siginfo_t *info, void *signal_ucontext)
{
	int instruction_size = 0;
	uint8_t* opcode = NULL;
	int result = 0;
    map_t *map = NULL;
    error_t status = SUCCESS;

	if (NULL == signal_ucontext) {
		thats_all_folks();
	}


	/* get the signal frame from the ucontext */
	context.context = (ucontext_t*)(signal_ucontext);
	context.fault_addr = info->si_addr;

    status = find_map(context.fault_addr, &map);
    if (SUCCESS != status) {
        thats_all_folks();
    }

	fprintf(context.log, "fault addr: 0x%x\n", (unsigned int)context.fault_addr);

	/* opcode which caused the segfault is at eip */
	opcode = (uint8_t*) INST_PTR(context.context);

	/* process opcode */
	instruction_size = process_opcode(opcode);

	if (!instruction_size) {
		thats_all_folks();
	}

	/* set a breakpoint after the instruction */
	opcode += instruction_size;
	status = set_breakpoint(opcode);
	if (SUCCESS != status) {
		thats_all_folks();
		goto l_exit;
	}

	/* unprotect do the instruction 
	* we will return the protection at SIGTAP hanlder */
	unprotect(map);

	fprintf(context.log, "value before : 0x%x\n", *context.fault_addr);

	/* return to the program context until SIGTRAP */
l_exit:
	return;
}

/*
 * Initialize
 */
static void segfault_init(void)
{
#define REPLACE(a, x, y)						\
	if ( !(o_##x = dlsym(a , y)) ) {				\
		fprintf(stderr, y"() not found in libc!\n");		\
                exit(-1);						\
	}

	struct sigaction action = {{0}};
	struct sigaction trap_action = {{0}};

	if ( (libc_handle = dlopen("libc.so", RTLD_NOW)) == NULL)
		if ( (libc_handle = dlopen("libc.so.6", RTLD_NOW)) == NULL)
			fprintf(stderr, "error loading libc!");

	/* get the address of the original signal() -function in libc */
	REPLACE(libc_handle, signal, "signal");

	/* get the address of the original sigaction() -function in libc */
	REPLACE(libc_handle, sigaction, "sigaction");

	/* get the address of the original mmap() -function in libc */
	REPLACE(libc_handle, mmap, "mmap");

	/* redirect action for these signals to our functions */
	action.sa_flags = SA_SIGINFO;
	action.sa_sigaction = segfault_handler;
	o_sigaction(SIGSEGV, &action, NULL);
	trap_action.sa_flags = SA_SIGINFO;
	trap_action.sa_sigaction = trap_handler;
	o_sigaction(SIGTRAP, &trap_action, NULL);

	if (getenv("SF_LOGFILE")) {
		context.log = fopen(getenv("SF_LOGFILE"), "w");
		printf("open : %s\n", getenv("SF_LOGFILE"));
	} else {
		context.log = stderr;
	}



	/* init the disassmbler (udis86) */
	ud_init(&(context.disasm));
	ud_set_mode(&(context.disasm), CPU_MODE);
	ud_set_syntax(&(context.disasm), UD_SYN_INTEL);
#undef REPLACE
}

/*
 * called by dynamic loader.
 */
static void init(void) __attribute__((constructor));
static void init(void)
{
	context.log = stderr;
	segfault_init();
}

static void fini(void) __attribute__((destructor));
static void fini(void)
{
	if (context.log != stderr) {
		fclose(context.log);
	}
}
