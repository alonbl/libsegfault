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
#include <execinfo.h>
#include <errno.h>

#define MAX_NUM_OF_MAPS 13
#define MAX_NUM_OF_BREAKS 13

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
#define BREAKPOINT 0xcc
#define MAX_INST_SIZE 16 /* FIXME: */
#define INST_PTR(context) ((context)->uc_mcontext.gregs[REG_EIP])
#elif defined(__x86_64)
#define ADDR_TYPE uint64_t
#define CPU_MODE 64 
#define BREAKPOINT 0xcc
#define MAX_INST_SIZE 16 /* FIXME: */
#define INST_PTR(context) ((context)->uc_mcontext.gregs[REG_RIP])
#else
#error unsupported architecture
#endif

#define page_align(address)  (char*)((unsigned long)(address) & -(getpagesize()))

typedef enum {
    FALSE = 0,
    TRUE
} bool;

typedef struct {
	void *mmap_addr;
	void *addr;
	size_t size;
	unsigned long saddr;
	unsigned long eaddr;
	void *fault_addr;
} map_t;

/* TODO: maybe we can save map_t and breakpoint_t togther? */
typedef struct {
    bool is_used;
	uint8_t *inst_addr;
	uint8_t inst_part;
    map_t *map;
} breakpoint_t;

/* Structure storing everythings we need to know */
typedef struct {
	ud_t disasm;
	FILE *log;

    map_t maps[MAX_NUM_OF_MAPS];
    size_t map_count;

    breakpoint_t breakpoints[MAX_NUM_OF_BREAKS];
} segfault_t;

typedef enum segfault_error_e {
    SEGFAULT_SUCCESS = 0,
    SEGFAULT_ADDR_NOT_FOUND,
    SEGFAULT_TOO_MANY_MAPS,
    SEGFAULT_TOO_MANY_BREAKS,
    SEGFAULT_MPROTECT_FAILD
} segfault_error_t;

typedef void (*sighandler_t)(int);

/*
 * o_signal is a ptr to original libc signal handler
 * o_mmap is a ptr to original libc mmap function
 * libc_handle
 */
static 
sighandler_t 
(* o_signal)(
        int, 
        sighandler_t
);

static 
int
(* o_sigaction)(
        int,
        const struct sigaction*,
        struct sigaction*
);

static 
void* 
(* o_mmap)(
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
static
void
thats_all_folks(
        void
)
{
    void *array[10];
    size_t size;

	fprintf(context.log, "That's all folks !\n");

    /* print traceback */
    size = backtrace(array, 10);
    backtrace_symbols_fd(array, size, 2);

    exit(-1);
}

/*
 * allocate a new map struct on the global pool (context)
 */
static 
segfault_error_t 
alloc_map(
        map_t **map
)
{
    /* check if we have reach the end of the pool */
    if (MAX_NUM_OF_MAPS <= context.map_count) {
        return SEGFAULT_TOO_MANY_MAPS;
    }

    *map = &context.maps[context.map_count];
    context.map_count++;

    return SEGFAULT_SUCCESS;
}

/*
 * find if the addr is in one of the maps in the global pool 
 * if it is, the function return's the relevent map
 */
static 
segfault_error_t 
find_map(
        void *addr,
        map_t **map
)
{
    unsigned long i = 0;
    segfault_error_t status = SEGFAULT_SUCCESS;

    /* we iterate over all the maps and see if the address is in one of them */
    for (; i < context.map_count; i++) {
        if ((context.maps[i].saddr <= (unsigned long)addr) &&
            (context.maps[i].eaddr >= (unsigned long)addr)) {
            /* we found the right map */
            *map = &context.maps[i];
            goto l_exit;
        }
    }
    
    /* the address is not in one of the maps */
    status = SEGFAULT_ADDR_NOT_FOUND;

l_exit:
    return status;
}

/*
 * allocate a breakpoint struct on the global pool (context)
 */
static 
segfault_error_t
alloc_breakpoint(
        breakpoint_t **breakpoint
)
{
    unsigned long i = 0;
    segfault_error_t status = SEGFAULT_SUCCESS;

    for (i=0; i < MAX_NUM_OF_BREAKS; i++) {
        if (FALSE == context.breakpoints[i].is_used) {
            /* unused breakpoint struct found */
            context.breakpoints[i].is_used = TRUE;
            *breakpoint = &context.breakpoints[i];
            goto l_exit;
        }
    }

    status =  SEGFAULT_TOO_MANY_BREAKS;

l_exit:
    return status;
}

/*
 * delete a breakpoint struct from the global pool (context)
 */
static 
segfault_error_t
del_breakpoint(
        breakpoint_t *breakpoint
)
{
    breakpoint->is_used = FALSE;
    memset(breakpoint, 0, sizeof(*breakpoint));
    
    return SEGFAULT_SUCCESS;
}

/*
 * find if there is a breakpoint with a spsific addr
 */
static 
segfault_error_t
find_breakpoint(
        void *addr,
        breakpoint_t **breakpoint
)
{
    segfault_error_t status = SEGFAULT_SUCCESS;

    unsigned long i = 0;
    /* iterate over all the breakpoints */
    for (i=0; i < MAX_NUM_OF_BREAKS; i++) {
        if ((context.breakpoints[i].inst_addr == addr) &&
            (context.breakpoints[i].is_used == TRUE)) {
            /* we found the right breakpoint */
            *breakpoint = &context.breakpoints[i];
            goto l_exit;
        }
    }
    /* there is no breakpoint at that address */
    status = SEGFAULT_ADDR_NOT_FOUND;
l_exit:
    return status;
}

/*
 * Protect memory
 */
static 
void 
protect(
        map_t *map
)
{
	if (mprotect(map->addr, map->size, PROT_NONE) < 0) {
		fprintf(
			context.log,
			"mprotect(0x%08X|0x%08X) failed\n", 
			(unsigned int)map->addr,
			map->size
		);
		thats_all_folks();
	}
}

/*
 * Unprotect memory
 */
static 
void 
unprotect(
        map_t *map
)
{
	if (mprotect(map->addr, map->size, PROT_READ | PROT_WRITE) < 0) {
		fprintf(
			context.log,
			"mprotect(0x%08X|0x%08X) failed\n", 
			(unsigned int)map->addr,
			map->size
		);
		thats_all_folks();
	}
}

/*
 * For library testing (or i am not root on my office computer ;))
 */
void 
libsegfault_protect(
        void* addr,
        size_t size,
        FILE* log
)
{
    map_t *map = NULL;
    segfault_error_t status = SEGFAULT_SUCCESS;

    /* add another map to the maping list */
    status = alloc_map(&map);
    if (SEGFAULT_SUCCESS != status) {
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
void*
mmap(
    void *addr,
    size_t len,
    int prot,
    int flags,
    int fildes,
    off_t off
)
{
    map_t *map = NULL;
    segfault_error_t status = SEGFAULT_SUCCESS;

    /* add another map to the maping list */
    status = alloc_map(&map);
    if (SEGFAULT_SUCCESS != status) {
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
int 
sigaction(
        int sn,
        const struct sigaction *act,
        struct sigaction *oldact
)
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
sighandler_t 
signal(
        int sn,
        sighandler_t sighandler
)
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



/* 
 * create a breakpoint at a wanted address and return the breakpoint struct
 */
static 
segfault_error_t 
set_breakpoint(
        void *addr,
        breakpoint_t **breakpoint
)
{
	int result = 0;
    breakpoint_t *_breakpoint = NULL;
    segfault_error_t status = SEGFAULT_SUCCESS;

    /* check if there is already breakpoint there if there is something is wrong */
    if (find_breakpoint(addr, &_breakpoint) == SEGFAULT_SUCCESS) {
        /* something is defnitly worng */
        thats_all_folks();
    }

    /* get a new breakpoint struct */
    status = alloc_breakpoint(&_breakpoint);
    if (SEGFAULT_SUCCESS != status) {
        goto l_exit;
    }

    /* save the instraction address and content for later use (when removing the break) */
	_breakpoint->inst_addr = (uint8_t*)addr;
	_breakpoint->inst_part = *(uint8_t*)addr;

	/* FIXME: change the premisstions back to the orginal */
	result = mprotect(
		(void*)(page_align(_breakpoint->inst_addr)),
		getpagesize(),
		PROT_READ | PROT_WRITE | PROT_EXEC
	);
	if (result < 0) {
        status = SEGFAULT_MPROTECT_FAILD;
		fprintf(
			context.log,
			"set_breakpoint mprotect failed errno:%d\n",
            errno
		);
		goto l_exit;
	}


	/* set the breakpoint opcode */
	*_breakpoint->inst_addr = BREAKPOINT;
    *breakpoint = _breakpoint;

l_exit:
	return status;
}

/* 
 * remove a breakpoint
 */
static 
segfault_error_t 
remove_breakpoint(
        breakpoint_t *breakpoint
)
{
    /* remove the break by changing the instruction back to the old instruction */
	*breakpoint->inst_addr = breakpoint->inst_part;

    return SEGFAULT_SUCCESS;
}

/*
 * Process opcode which caused the segfault
 */
static 
int 
process_opcode(
        uint8_t* opcode
)
{
	unsigned int size = 0;

    /* we use the udis86 to disassmble the opcode and find out it's size */
	ud_set_input_buffer(&(context.disasm), opcode, MAX_INST_SIZE);
	size = ud_disassemble(&(context.disasm));
	fprintf(context.log,"\t%s\n", ud_insn_asm(&(context.disasm)));

	return size;
}


/* FIXME: can create starvetion? */
static 
void 
trap_handler(
        int sig,
        siginfo_t *info,
        void *signal_ucontext
)
{
    breakpoint_t *breakpoint;
    void *addr = NULL;
    segfault_error_t status = SEGFAULT_SUCCESS;

    addr = (void*)((unsigned long)INST_PTR((ucontext_t*)(signal_ucontext)) -1);
    
    /* find the correct breakpoint struct for the given address */
    status = find_breakpoint(addr, &breakpoint);
	if (SEGFAULT_SUCCESS != status) {
        goto l_exit;
	}


    /* remove the breakpoint */
    status = remove_breakpoint(breakpoint);
    if (SEGFAULT_SUCCESS != status) {
        thats_all_folks();
    }
    
	fprintf(context.log, "value after : 0x%x\n", (ADDR_TYPE)breakpoint->map->fault_addr);

    /* return the instruction pointer back to execute the instruction */
    INST_PTR((ucontext_t*)(signal_ucontext))--;


	protect(breakpoint->map);

    del_breakpoint(breakpoint);

l_exit:
    return;
}

/*
 * All the segfault handling fun happen here
 */
static 
void 
segfault_handler(
        int sig,
        siginfo_t *info,
        void *signal_ucontext
)
{
	int instruction_size = 0;
	uint8_t* opcode = NULL;
	int result = 0;
    void *fault_addr = NULL;
    ucontext_t *ucontext = NULL;
    map_t *map = NULL;
    breakpoint_t *breakpoint = NULL;
    segfault_error_t status = SEGFAULT_SUCCESS;

	if (NULL == signal_ucontext) {
		thats_all_folks();
	}


	/* get the signal frame from the ucontext */
	ucontext = (ucontext_t*)(signal_ucontext);
	fault_addr = info->si_addr;

    /* try to find the right map which cause the fault */
    status = find_map(fault_addr, &map);
    if (SEGFAULT_SUCCESS != status) {
        /* this means that the segfault wasn't our fault */
        thats_all_folks();
    }

	fprintf(context.log, "fault addr: 0x%x\n", (ADDR_TYPE)fault_addr);

	/* opcode which caused the segfault is at eip */
	opcode = (uint8_t*) INST_PTR(ucontext);

	/* process opcode */
	instruction_size = process_opcode(opcode);

	if (!instruction_size) {
		thats_all_folks();
	}

	/* set a breakpoint after the instruction */
	opcode += instruction_size;
	status = set_breakpoint(opcode, &breakpoint);
	if (SEGFAULT_SUCCESS != status) {
		thats_all_folks();
		goto l_exit;
	}

    /* set the current map and the fault_addr for later use */
    map->fault_addr = fault_addr;
    breakpoint->map = map;

	/* unprotect do the instruction 
	* we will return the protection at SIGTAP hanlder */
	unprotect(map);

	fprintf(context.log, "value before : 0x%x\n", (ADDR_TYPE)fault_addr);

	/* return to the program context until SIGTRAP */
l_exit:
	return;
}

/*
 * Initialize
 */
static
void 
segfault_init(void)
{
#define REPLACE(a, x, y)						\
	if ( !(o_##x = dlsym(a , y)) ) {				\
		fprintf(stderr, y"() not found in libc!\n");		\
                exit(-1);						\
	}

	struct sigaction fault_action;
	struct sigaction trap_action;

    /* initialize the action structs */
    memset(&fault_action, 0,sizeof(fault_action));
    memset(&trap_action, 0,sizeof(trap_action));

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
	fault_action.sa_flags = SA_SIGINFO;
	fault_action.sa_sigaction = segfault_handler;
	o_sigaction(SIGSEGV, &fault_action, NULL);
	trap_action.sa_flags = SA_SIGINFO | SA_ONSTACK;
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

static 
void 
init(void)
{
	context.log = stderr;
	segfault_init();
}

static void fini(void) __attribute__((destructor));

static
void 
fini(void)
{
	if (context.log != stderr) {
		fclose(context.log);
	}
}
