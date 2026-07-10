/*
 * rootshell — SUID root escalation shell for Orbic RCL400
 *
 * Mirrors Rayhunter's rootshell (rootshell/src/main.rs).
 * When this binary is owned by root and has the SUID bit set (chmod 4755),
 * it escalates the caller (ADB shell uid=2000) to uid=0 and exec's /bin/sh.
 *
 * Usage:
 *   /bin/rootshell              — interactive root shell
 *   /bin/rootshell -c "cmd"     — run cmd as root
 *
 * Build (from orbic_fw_c/):
 *   export PATH="$PWD/../gcc_mac/bin:$PATH"
 *   arm-cortex_a8-linux-gnueabi-gcc -static -Os -nostdinc \
 *       -o rootshell rootshell.c
 */

/* Avoid broken sysroot headers — declare only what we need.
 * Function implementations come from glibc (libc.a for static linking). */
typedef unsigned int gid_t;
typedef unsigned int uid_t;

extern int setgroups(int size, const gid_t *list);
extern int setgid(gid_t gid);
extern int setuid(uid_t uid);
extern int execv(const char *path, char *const argv[]);
extern long write(int fd, const void *buf, long count);
extern void _exit(int status);

int main(int argc, char *argv[]) {
    /* Android "paranoid networking" — supplementary groups for socket access */
    gid_t groups[] = { 3003, 3004 };  /* AID_INET, AID_NET_RAW */
    setgroups(2, groups);

    /* Escalate to root (works because binary is SUID root) */
    setgid(0);
    setuid(0);

    /* Exec /bin/sh, passing through any arguments (e.g. -c "command") */
    argv[0] = "/bin/sh";
    execv("/bin/sh", argv);

    /* Only reached on error */
    write(2, "rootshell: execv failed\n", 24);
    _exit(1);
    return 1;
}
