#include <syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef __aarch64__
__attribute__((naked)) static long mysyscall1(unsigned long a0, unsigned long nr) {
    asm volatile("mov x8, x1\nsvc 0\nret\n":::"x8");
}
__attribute__((naked)) static long mysyscall3(
    unsigned long a0, unsigned long a1, unsigned long a2, unsigned long nr) {
    asm volatile("mov x8, x3\nsvc 0\nret\n":::"x8");
}
__attribute__((naked)) static long mysyscall4(
    unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3,
    unsigned long nr) {
    asm volatile("mov x8, x4\nsvc 0\nret\n":::"x8");
}
__attribute__((naked)) static long mysyscall6(
    unsigned long a0, unsigned long a1, unsigned long a2,
    unsigned long a3, unsigned long a4, unsigned long a5, unsigned long nr) {
    asm volatile("mov x8, x6\nsvc 0\nret\n":::"x8");
}
__attribute__((naked)) void _start() {
    asm(".extern start_c\nmov x0, sp\nb start_c\n");
}
#elif defined(__arm__)
__attribute__((naked)) static long mysyscall1(unsigned long a0, unsigned long nr) {
    asm volatile("mov r7, r1\nsvc 0\nbx lr\n":::"r7");
}
__attribute__((naked)) static long mysyscall3(
    unsigned long a0, unsigned long a1, unsigned long a2, unsigned long nr) {
    asm volatile("mov r7, r3\nsvc 0\nbx lr\n":::"r7");
}
__attribute__((naked)) static long mysyscall4(
    unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3,
    unsigned long nr) {
    asm volatile("push {r7}\nldr r7, [sp, #4]\nsvc 0\npop {r7}\nbx lr\n":::"memory");
}
__attribute__((naked)) static long mysyscall6(
    unsigned long a0, unsigned long a1, unsigned long a2,
    unsigned long a3, unsigned long a4, unsigned long a5, unsigned long nr) {
    asm volatile(
        "push {r4, r5, r7}\n"
        "ldr r4, [sp, #12]\n"
        "ldr r5, [sp, #16]\n"
        "ldr r7, [sp, #20]\n"
        "svc 0\n"
        "pop {r4, r5, r7}\n"
        "bx lr\n"
        :::"memory");
}
__attribute__((naked)) void _start() {
    asm(".extern start_c\nmov r0, sp\nb start_c\n");
}
#endif

static const char dev_df[] = "/dev/df";
static const char ko_path[] = "/vendor/lib/libbinderdebug.so";

#define KO_MAX_SIZE 65536

void start_c(void *argblock) {
    (void)argblock;

    int mfd = (int)mysyscall4(
        (unsigned long)AT_FDCWD,
        (unsigned long)dev_df,
        (unsigned long)(O_CREAT | O_EXCL | O_CLOEXEC),
        0,
        __NR_openat);
    if (mfd >= 0)
        mysyscall1((unsigned long)mfd, __NR_close);

    int fd = (int)mysyscall4(
        (unsigned long)AT_FDCWD,
        (unsigned long)ko_path,
        (unsigned long)O_RDONLY,
        0,
        __NR_openat);
    if (fd < 0)
        mysyscall1(1, __NR_exit_group);

#ifdef __aarch64__
    void *map = (void *)mysyscall6(
        0, KO_MAX_SIZE, PROT_READ, MAP_PRIVATE, (unsigned long)fd, 0, __NR_mmap);
#else
    void *map = (void *)mysyscall6(
        0, KO_MAX_SIZE, PROT_READ, MAP_PRIVATE, (unsigned long)fd, 0, __NR_mmap2);
#endif
    mysyscall1((unsigned long)fd, __NR_close);

    if ((long)map < 0)
        mysyscall1(2, __NR_exit_group);

    unsigned char *p = (unsigned char *)map;
    unsigned long ko_size = 0;
    if (p[0] == 0x7f && p[1] == 'E' && p[2] == 'L' && p[3] == 'F') {
#ifdef __aarch64__
        ko_size = *(unsigned long *)(p + 40);
#else
        ko_size = *(unsigned long *)(p + 32);
#endif
    }
    if (!ko_size || ko_size > KO_MAX_SIZE)
        ko_size = KO_MAX_SIZE;

    mysyscall3((unsigned long)map, ko_size, (unsigned long)"", __NR_init_module);

    mysyscall1(0, __NR_exit_group);
}
