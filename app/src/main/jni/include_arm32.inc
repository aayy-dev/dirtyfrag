  @ ARM32 EABI syscall numbers and constants for libcxx_arm32.S

  .equ SYS_exit,            1
  .equ SYS_read,            3
  .equ SYS_write,           4
  .equ SYS_open,            5
  .equ SYS_close,           6
  .equ SYS_execve,         11
  .equ SYS_lseek,          19
  .equ SYS_getuid32,      199
  .equ SYS_clone,         120
  .equ SYS_gettid,        224
  .equ SYS_openat,        322

  .equ SIGCHLD,            17
  .equ CLONE_CHILD_SETTID,  0x01000000
  .equ CLONE_CHILD_CLEARTID, 0x00200000

  .equ O_RDONLY,  00000000
  .equ O_WRONLY,  00000001
  .equ O_CREAT,  00000100
  .equ O_EXCL,   00000200
  .equ O_CLOEXEC, 02000000

  .macro movl Rd, imm
      movw    \Rd, #(\imm) & 0xffff
      .if (\imm) >> 16
      movt    \Rd, #(\imm) >> 16
      .endif
  .endm
