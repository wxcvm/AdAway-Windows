#ifndef ADBLOCK_GUI_ASSIST_DIALOGS_WIN32_H
#define ADBLOCK_GUI_ASSIST_DIALOGS_WIN32_H

#include <windows.h>
#include <stdbool.h>
#include <stddef.h>

/* Immutable UI snapshot: dialogs must not depend on dashboard globals.
 * They only report diagnostics; they NEVER modify DNS or system routing. */
struct gui_adguard_runtime {
    bool bind_all;
    bool listener_responding;
    bool ca_trusted_for_user;
    int http_port;
    int https_port;
};
typedef int (*gui_lookup_lan_ipv4)(char *out, size_t size);

void gui_show_adguard_home_wizard(HWND hwnd,
                                  const struct gui_adguard_runtime *state,
                                  gui_lookup_lan_ipv4 find_lan_ipv4);
void gui_show_network_baseline(HWND hwnd);

#endif
