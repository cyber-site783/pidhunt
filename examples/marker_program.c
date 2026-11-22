/* marker_program.c - lab target for PidHunt.
 *
 * Holds planted markers in memory so PidHunt can find them.
 * Only run this on your own machine, for your own lab.
 *
 * Compile:  gcc -O2 -o marker_program marker_program.c
 * Run:      ./marker_program        (prints its PID, then sleeps)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* Marker 1 - plain string (lives in .rodata, readable). */
static const char secret_marker[] = "PIDHUNT_SECRET_MARKER_12345";

/* Marker 2 - hex byte sequence (lives in .rodata, readable). */
static const unsigned char hex_marker[] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04
};

/* Marker 3 - text matched by a regex rule (lives in .rodata, readable). */
static const char password_line[] = "password=Hunter2!";

int main(void) {
    /* A dedicated anonymous region filled with random bytes.
       Its entropy is close to 8 bits per byte, so PidHunt --entropy
       flags it HIGH - a stand-in for packed or encrypted data.
       64 KiB, so the random bytes dominate the region even if the
       kernel merges it with a neighbouring anonymous mapping. */
    const size_t random_len = 64 * 1024;
    unsigned char *random_buf = mmap(NULL, random_len, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (random_buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom || fread(random_buf, 1, random_len, urandom) != random_len) {
        perror("urandom");
        return 1;
    }
    fclose(urandom);

    printf("marker_program PID: %d\n", getpid());
    printf("secret marker: %s\n", secret_marker);
    printf("hex marker: ");
    for (size_t i = 0; i < sizeof(hex_marker); i++) {
        printf("%02X", hex_marker[i]);
    }
    printf("\npassword line: %s\n", password_line);
    printf("random buffer at %p (%zu bytes, high entropy)\n",
           (void *)random_buf, random_len);
    fflush(stdout);

    /* Stay alive so PidHunt can scan this process. */
    for (;;) {
        sleep(60);
    }
    return 0;
}
