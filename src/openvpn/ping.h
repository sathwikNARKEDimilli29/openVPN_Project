#ifndef PING_H
#define PING_H

#include "init.h"
#include "forward.h"

/*
 * Initial default --ping-restart before --pull
 */
#define PRE_PULL_INITIAL_PING_RESTART 120  /* in seconds */

extern const uint8_t ping_string[];

/* PING_STRING_SIZE must be sizeof (ping_string) */
#define PING_STRING_SIZE 16

static inline bool
is_ping_msg(const struct buffer *buf)
{
    return buf_string_match(buf, ping_string, PING_STRING_SIZE);
}

/**
 * Trigger the correct signal on a --ping timeout
 * depending if --ping-exit is set (SIGTERM) or not
 * (SIGUSR1)
 */
void trigger_ping_timeout_signal(struct context *c);

/**
 * Perform actions to send a ping packet and set a timeout
 * for the ping operation.
 * 
 * @param c      The context containing the necessary information for sending ping
 * @param timeout The timeout duration for the ping operation
 */
void check_ping_send_dowork(struct context *c, int timeout);

/*
 * Should we exit or restart due to ping (or other authenticated packet)
 * not received in n seconds?
 */
static inline void
check_ping_restart(struct context *c, int timeout)
{
    if (c->options.ping_rec_timeout
        && event_timeout_trigger(&c->c2.ping_rec_interval,
                                 &c->c2.timeval,
                                 (!c->options.ping_timer_remote
                                  || link_socket_actual_defined(&c->c1.link_socket_addr.actual))
                                 ? ETT_DEFAULT : timeout))
    {
        trigger_ping_timeout_signal(c);
    }
}

/*
 * Should we ping the remote?
 */
static inline void
check_ping_send(struct context *c, int timeout)
{
    if (c->options.ping_send_timeout
        && event_timeout_trigger(&c->c2.ping_send_interval,
                                 &c->c2.timeval,
                                 !TO_LINK_DEF(c) ? ETT_DEFAULT : timeout))
    {
        check_ping_send_dowork(c, timeout);
    }
}

#endif /* ifndef PING_H */
