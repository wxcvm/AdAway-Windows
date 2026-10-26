#!/usr/bin/env bash
# Source from a build script with HERE set to the repository root.
# Keep the production dashboard and its GUI acceptance driver linked identically.
GUI_SOURCES=(
"$HERE/gui_win32.c" "$HERE/gui_assist_dialogs_win32.c" "$HERE/update_win32.c" "$HERE/update_feed.c"
  "$HERE/subscription_update_win32.c" "$HERE/subscription_settings_win32.c" "$HERE/subscription_display_win32.c" "$HERE/policy_settings_win32.c" "$HERE/dns_policy_wire.c"
  "$HERE/listener_arrival_win32.c" "$HERE/listener_arrival_dialog_win32.c" "$HERE/listener_arrival_task_win32.c" "$HERE/restart_win32.c"
  "$HERE/listener_tls_win32.c" "$HERE/isolated_transport_win32.c" "$HERE/isolated_tcp_win32.c" "$HERE/isolated_transport_dialog_win32.c"
  "$HERE/traffic_mode_policy.c" "$HERE/traffic_observer_win32.c"
  "$HERE/adguard_home_plan.c" "$HERE/windows_capture_plan.c"
  "$HERE/wintun_probe_win32.c" "$HERE/windows_network_inventory_win32.c"
  "$HERE/windows_network_journal.c" "$HERE/windows_network_journal_store_win32.c"
)
