#ifndef ADBLOCK_TRAFFIC_OBSERVER_WIN32_H
#define ADBLOCK_TRAFFIC_OBSERVER_WIN32_H

/* Observing a process is a HINT ONLY; it is never sufficient to infer that
 * AdGuard is intercepting packets or to automatically change network modes. */
enum adguard_process_signal {
    ADGUARD_PROCESS_UNKNOWN = -1,
    ADGUARD_PROCESS_ABSENT = 0,
    ADGUARD_PROCESS_PRESENT = 1
};

enum adguard_process_signal adguard_process_probe(void);

#endif
