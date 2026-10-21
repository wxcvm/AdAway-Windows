#ifndef ADBLOCK_ISOLATED_TCP_H
#define ADBLOCK_ISOLATED_TCP_H
#include "isolated_transport_win32.h"
enum tcp_fixture { TCP_NORMAL, TCP_SILENT, TCP_STALE, TCP_TRUNCATED, TCP_BAD_AUTH, TCP_BAD_TARGET, TCP_OVERSIZE };
struct tcp_options { unsigned family, budget_ms; HANDLE cancel, ready; enum tcp_fixture fixture; };
/* One bounded authenticated CONNECT transaction on ephemeral loopback sockets.
 * No external destination, driver, route, system proxy or persistent listener. */
void isolated_tcp_run(const struct tcp_options *options, struct it_result *result);
#endif
