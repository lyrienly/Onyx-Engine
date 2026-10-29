#ifdef __TINYC__

unsigned _tccsyscall(unsigned syscall_nr, ...);

__asm__(
    ".global _tccsyscall\n"
    "_tccsyscall:\n"
    ".int 0xe92d4080\n"
    ".int 0xe1a07000\n"
    ".int 0xe1a00001\n"
    ".int 0xe1a01002\n"
    ".int 0xe1a02003\n"
    ".int 0xef000000\n"
    ".int 0xe8bd8080\n"
    );

#if defined(__thumb__) || defined(__ARM_EABI__)
# define __NR_SYSCALL_BASE      0x0
#else
# define __NR_SYSCALL_BASE      0x900000
#endif
#define __ARM_NR_BASE           (__NR_SYSCALL_BASE+0x0f0000)
#define __ARM_NR_cacheflush     (__ARM_NR_BASE+2)

#define syscall _tccsyscall

#else

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

#endif

void __clear_cache(void *beginning, void *end)
{

#if 1
    syscall(__ARM_NR_cacheflush, beginning, end, 0);
#else
    __asm__ ("push {r7}\n\t"
             "mov r7, #0xf0002\n\t"
             "mov r2, #0\n\t"
             "swi 0\n\t"
             "pop {r7}\n\t"
             "ret");
#endif
}
