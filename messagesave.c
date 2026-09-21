/*
 * messagesave.c — Save a message from a fixed-size network frame.
 *
 * Reads a frame from stdin (simulating recv() on a socket).
 * Validates the message length by counting ASCII-printable bytes
 * (0x20-0x7E). Copies the frame using the actual number of bytes
 * read. Every buffer write is bounds-checked. Every copy uses a
 * safe function. There is no length miscalculation.
 *
 * The bug is purely an encoding assumption:
 *
 *   count_printable_ascii() counts bytes in the ASCII printable
 *   range. This is correct for ASCII input. For EBCDIC input,
 *   EBCDIC letters fall outside 0x20-0x7E, so the count is far
 *   smaller than the actual byte count. The validation passes
 *   when it should fail, and the copy overflows.
 *
 * For ASCII input:  count == byte count  -> validation correct -> safe.
 * For EBCDIC input: count << byte count  -> validation wrong  -> overflow.
 *
 * The frame buffer lives in .bss, not on the stack, so it does not
 * overlap with `msg` in main's frame. This isolates the overflow so
 * ASAN reports stack-buffer-overflow instead of memcpy-param-overlap.
 *
 * Compile (normal):
 *   gcc -o messagesave messagesave.c -fno-stack-protector -no-pie -g
 *
 * Compile (ASAN):
 *   gcc -o messagesave_asan messagesave.c -fsanitize=address -g
 *
 * FOR AUTHORIZED LAB USE ONLY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FRAME 512
#define MAX_MSG   64

/* Global frame buffer — lives in .bss, not on the stack. */
static char g_frame[MAX_FRAME];

struct message {
    char text[MAX_MSG];
};

/*
 * count_printable_ascii()
 *
 * Counts bytes in the ASCII printable range 0x20-0x7E.
 * Correct for ASCII input. For EBCDIC input, most bytes fall
 * outside this range, so the count is much smaller than the
 * actual byte count.
 *
 * This is the ONLY encoding-dependent piece of logic in the
 * program, and it is the root cause of the vulnerability.
 */
static size_t count_printable_ascii(const char *buf, size_t n) {
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c >= 0x20 && c <= 0x7E) {
            count++;
        }
    }
    return count;
}

/*
 * validate_and_copy()
 *
 * frame        — raw bytes
 * frame_size   — how many bytes were read
 * msg          — destination struct (on the stack of the caller)
 *
 * Validates using the ASCII-printable count.
 * Copies using the actual frame size.
 *
 * For ASCII input, validated_len == frame_size, so the check is
 * correct. For EBCDIC input, validated_len << frame_size, so the
 * check passes even for a 400-byte frame, and the copy overflows.
 */
static int validate_and_copy(const char *frame, size_t frame_size,
                             struct message *msg) {
    size_t validated_len = count_printable_ascii(frame, frame_size);

    fprintf(stderr,
            "[messagesave] DEBUG: frame_size=%zu printable_ascii=%zu MAX_MSG=%d\n",
            frame_size, validated_len, MAX_MSG);

    /*
     * Validate against the printable-ASCII count.
     * Correct for ASCII input. Wrong for EBCDIC input.
     */
    if (validated_len >= MAX_MSG) {
        fprintf(stderr,
                "[messagesave] rejected: printable_count=%zu >= MAX_MSG=%d\n",
                validated_len, MAX_MSG);
        return -1;
    }

    /*
     * Copy using the actual byte count.
     * For ASCII, frame_size == validated_len, so this is safe.
     * For EBCDIC, frame_size >> validated_len, so this overflows.
     */
    fprintf(stderr,
            "[messagesave] copying %zu bytes into %d-byte buffer\n",
            frame_size, MAX_MSG);
    memcpy(msg->text, frame, frame_size);
    msg->text[frame_size] = '\0';

    return 0;
}

int main(void) {
    struct message msg;

    memset(&msg, 0, sizeof(msg));

    fprintf(stderr, "[messagesave] reading frame...\n");

    /*
     * Read into the global g_frame. read() does not add a null
     * terminator and does not stop at newline — same semantics as
     * recv() on a socket.
     */
    ssize_t n = read(STDIN_FILENO, g_frame, sizeof(g_frame));
    if (n <= 0) {
        fprintf(stderr, "[messagesave] no data\n");
        return 1;
    }

    fprintf(stderr, "[messagesave] read %zd bytes\n", n);

    if (validate_and_copy(g_frame, (size_t)n, &msg) != 0) {
        fprintf(stderr, "[messagesave] rejected\n");
        return 1;
    }

    fprintf(stderr, "[messagesave] accepted\n");
    return 0;
}