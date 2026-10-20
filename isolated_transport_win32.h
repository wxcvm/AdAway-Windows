#ifndef ADBLOCK_ISOLATED_TRANSPORT_H
#define ADBLOCK_ISOLATED_TRANSPORT_H
#include <winsock2.h>
#include <windows.h>
#include <stdbool.h>
enum it_status { IT_OK, IT_CANCELLED, IT_TIMEOUT, IT_INVALID, IT_SYSTEM_ERROR, IT_CLEANUP_FAILED };
enum it_fixture { IT_NORMAL, IT_SILENT, IT_STALE_REPLY, IT_BAD_PACKET };
struct it_options { unsigned family, budget_ms; HANDLE cancel, ready; enum it_fixture fixture; };
struct it_result { enum it_status status; unsigned family, elapsed_ms, sockets_opened, sockets_closed, error, stage; bool cleanup_ok; };
/* Fixed loopback fixtures + mock TUN IP frames. No driver/routes/DNS/system writes. */
void isolated_transport_run(const struct it_options *options, struct it_result *result);
const wchar_t *isolated_transport_status(enum it_status status);
void gui_show_transport_dialog(HWND owner);
#endif
