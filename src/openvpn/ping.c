#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "ping.h"

#include "memdbg.h"
#include <unistd.h>  // Include for sleep and usleep functions

/*
 * This random string identifies an OpenVPN ping packet.
 * It should be of sufficient length and randomness
 * so as not to collide with other tunnel data.
 *
 * PING_STRING_SIZE must be sizeof (ping_string)
 */
const uint8_t ping_string[] = {
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

void
trigger_ping_timeout_signal(struct context *c)
{
    struct gc_arena gc = gc_new();
    
    // Introduce a delay (timeout) to defeat fingerprinting technique
    usleep(50000);  // Sleep for 50 milliseconds (50,000 microseconds)

    switch (c->options.ping_rec_timeout_action)
    {
        case PING_EXIT:
            msg(M_INFO, "%sInactivity timeout (--ping-exit), exiting",
                format_common_name(c, &gc));
            register_signal(c->sig, SIGTERM, "ping-exit");
            break;

        case PING_RESTART:
            msg(M_INFO, "%sInactivity timeout (--ping-restart), restarting",
                format_common_name(c, &gc));
            register_signal(c->sig, SIGUSR1, "ping-restart");
            break;

        default:
            ASSERT(0);
    }
    gc_free(&gc);
}

/*
 * Should we ping the remote?
 */
void
check_ping_send_dowork(struct context *c)
{
    // Introduce a delay to match the timeout delay in the timeout signal
    usleep(50000);  // Sleep for 50 milliseconds (50,000 microseconds)

    c->c2.buf = c->c2.buffers->aux_buf;
    ASSERT(buf_init(&c->c2.buf, c->c2.frame.buf.headroom));
    ASSERT(buf_safe(&c->c2.buf, c->c2.frame.buf.payload_size));
    ASSERT(buf_write(&c->c2.buf, ping_string, sizeof(ping_string)));

    /*
     * We will treat the ping like any other outgoing packet,
     * encrypt, sign, etc.
     */
    encrypt_sign(c, true);
    /* Set length to 0, so it won't be counted as activity */
    c->c2.buf.len = 0;
    dmsg(D_PING, "SENT PING");
}
