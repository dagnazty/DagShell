 /*
 * rootshell.S — SUID root escalation shell for Orbic RCL400 (pure ARM asm)
 *
 * Mirrors Rayhunter's rootshell but as a standalone ELF with zero libc deps.
 * When owned by root with SUID bit (chmod 4755), escalates uid=2000 → uid=0.
 *
 * Build:
 *   arm-cortex_a8-linux-gnueabi-as -meabi=5 -o rootshell.o rootshell.S
 *   arm-cortex_a8-linux-gnueabi-ld -o rootshell rootshell.o
 *   arm-cortex_a8-linux-gnueabi-strip rootshell
 *
 * Usage: /bin/rootshell -c "command"   or   /bin/rootshell (interactive)
 *
 * Syscall numbers (ARM EABI, 32-bit):
 *   __NR_setgroups32 = 206
 *   __NR_setuid32    = 213
 *   __NR_setgid32    = 214
 *   __NR_execve      = 11
 */

    .text
    .global _start
    .arm

_start:
    /* ---- setgroups(2, [3003, 3004]) ---- */
    /* Android paranoid networking: AID_INET=3003, AID_NET_RAW=3004 */
    ldr     r1, =groups         @ r1 = pointer to groups array
    mov     r0, #2              @ r0 = count
    mov     r7, #206            @ __NR_setgroups32
    svc     #0

    /* ---- setgid(0) ---- */
    mov     r0, #0
    mov     r7, #214            @ __NR_setgid32
    svc     #0

    /* ---- setuid(0) ---- */
    mov     r0, #0
    mov     r7, #213            @ __NR_setuid32
    svc     #0

    /* ---- execve("/bin/sh", argv, environ) ----
     *
     * We rewrite argv[0] to point to "/bin/sh" so the shell sees the right
     * name, then pass the ORIGINAL argc/argv through (including any -c "cmd").
     *
     * On entry, the Linux process stack is:
     *   [sp+0]  = argc
     *   [sp+4]  = argv[0]
     *   [sp+8]  = argv[1]  ...
     *   after NULL terminator: envp[]
     *
     * We overwrite argv[0] and use the whole argv array as-is.
     */
    ldr     r3, =shell_path     @ r3 = "/bin/sh"
    ldr     r4, [sp]            @ r4 = argc
    add     r1, sp, #4          @ r1 = &argv[0]
    str     r3, [r1]            @ argv[0] = "/bin/sh"

    /* Find envp: skip past argv[] (argc+1 pointers including NULL) */
    add     r2, r4, #1          @ argc + 1 (for NULL terminator)
    add     r2, r1, r2, lsl #2  @ r2 = argv + (argc+1)*4 = envp

    mov     r0, r3              @ r0 = "/bin/sh" path
    /* r1 = argv, r2 = envp already set */
    mov     r7, #11             @ __NR_execve
    svc     #0

    /* If execve returns (error), exit(1) */
    mov     r0, #1
    mov     r7, #1              @ __NR_exit
    svc     #0

    .align  2
groups:
    .word   3003                @ AID_INET
    .word   3004                @ AID_NET_RAW

shell_path:
    .asciz  "/bin/sh"
