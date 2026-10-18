#include "dns_probe_win32.h"
#include "diagnostic_dns_reply.h"
#include "dns_policy_wire.h"
#include "block_rule_snapshot.h"
#include <string.h>

static enum dns_probe_status ready(SOCKET socket, int writing, ULONGLONG deadline, HANDLE cancel) {
    for (;;) {
        if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return DNS_PROBE_CANCELLED;
        ULONGLONG now = GetTickCount64();
        if (now >= deadline) return DNS_PROBE_TIMEOUT;
        unsigned long wait = (unsigned long)(deadline - now);
        if (wait > 25) wait = 25;
        struct timeval timeout = {0, (long)wait * 1000};
        fd_set active, errors; FD_ZERO(&active); FD_ZERO(&errors);
        FD_SET(socket, &active); FD_SET(socket, &errors);
        int count = select(0, writing ? NULL : &active, writing ? &active : NULL, &errors, &timeout);
        if (count == SOCKET_ERROR || FD_ISSET(socket, &errors)) return DNS_PROBE_IO;
        if (count > 0) return DNS_PROBE_OK;
    }
}
static enum dns_probe_status transfer(SOCKET socket, uint8_t *bytes, size_t size,
    int writing, ULONGLONG deadline, HANDLE cancel) {
    for (size_t at = 0; at < size;) {
        enum dns_probe_status status = ready(socket, writing, deadline, cancel);
        if (status != DNS_PROBE_OK) return status;
        int n = writing ? send(socket, (const char *)bytes + at, (int)(size - at), 0)
                        : recv(socket, (char *)bytes + at, (int)(size - at), 0);
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (n <= 0) return DNS_PROBE_IO;
        at += (size_t)n;
    }
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return DNS_PROBE_CANCELLED;
    return GetTickCount64() >= deadline ? DNS_PROBE_TIMEOUT : DNS_PROBE_OK;
}
static SOCKET open_socket(int type) {
    SOCKET value = socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    if (value == INVALID_SOCKET) return value;
    u_long enabled = 1;
    if (ioctlsocket(value, FIONBIO, &enabled) == SOCKET_ERROR) { closesocket(value); return INVALID_SOCKET; }
    return value;
}
static enum dns_probe_status exchange(unsigned short port, const uint8_t *query, size_t size,
    unsigned budget, HANDLE cancel, struct dns_probe_result *result) {
    ULONGLONG deadline = GetTickCount64() + budget;
    struct sockaddr_in endpoint; memset(&endpoint, 0, sizeof(endpoint));
    endpoint.sin_family = AF_INET; endpoint.sin_port = htons(port); endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    enum dns_probe_status status = DNS_PROBE_IO;
    SOCKET value = open_socket(SOCK_DGRAM);
    if (value == INVALID_SOCKET) return status;
    if (connect(value, (const struct sockaddr *)&endpoint, sizeof(endpoint)) == SOCKET_ERROR) goto done;
    status = ready(value, 1, deadline, cancel);
    if (status != DNS_PROBE_OK) goto done;
    if (send(value, (const char *)query, (int)size, 0) != (int)size) { status = DNS_PROBE_IO; goto done; }
    status = ready(value, 0, deadline, cancel);
    if (status != DNS_PROBE_OK) goto done;
    uint8_t buffer[DDNS_MAX + 1];
    int n = recv(value, (char *)buffer, sizeof(buffer), 0);
    if (n == SOCKET_ERROR) { status = WSAGetLastError() == WSAEMSGSIZE ? DNS_PROBE_BAD_REPLY : DNS_PROBE_IO; goto done; }
    if (GetTickCount64() >= deadline) { status = DNS_PROBE_TIMEOUT; goto done; }
    enum ddns_reply kind = ddns_classify(query, size, buffer, (size_t)n);
    if (kind == DDNS_ACCEPT) { memcpy(result->answer, buffer, (size_t)n); result->size = (size_t)n; status = DNS_PROBE_OK; goto done; }
    if (kind != DDNS_RETRY_TCP) { status = DNS_PROBE_BAD_REPLY; goto done; }
    closesocket(value); value = open_socket(SOCK_STREAM);
    if (value == INVALID_SOCKET) return DNS_PROBE_IO;
    result->via_tcp = 1;
    if (connect(value, (const struct sockaddr *)&endpoint, sizeof(endpoint)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS) { status = DNS_PROBE_IO; goto done; }
    }
    status = ready(value, 1, deadline, cancel);
    if (status != DNS_PROBE_OK) goto done;
    int error = 0, error_size = sizeof(error);
    if (getsockopt(value, SOL_SOCKET, SO_ERROR, (char *)&error, &error_size) == SOCKET_ERROR || error) { status = DNS_PROBE_IO; goto done; }
    uint8_t framed[DDNS_QUERY_SIZE + 2]; framed[0] = 0; framed[1] = (uint8_t)size; memcpy(framed + 2, query, size);
    status = transfer(value, framed, size + 2, 1, deadline, cancel);
    if (status != DNS_PROBE_OK) goto done;
    status = transfer(value, buffer, 2, 0, deadline, cancel);
    if (status != DNS_PROBE_OK) goto done;
    size_t length = ddns_u16(buffer, 0);
    if (length < DDNS_QUERY_SIZE || length > DDNS_MAX) { status = DNS_PROBE_BAD_REPLY; goto done; }
    status = transfer(value, buffer, length, 0, deadline, cancel);
    if (status != DNS_PROBE_OK) goto done;
    if (ddns_classify(query, size, buffer, length) != DDNS_ACCEPT) { status = DNS_PROBE_BAD_REPLY; goto done; }
    memcpy(result->answer, buffer, length); result->size = length;
done:
    closesocket(value);
    if (status != DNS_PROBE_OK) { result->size = 0; memset(result->answer, 0, sizeof(result->answer)); }
    return status;
}
enum dns_probe_status dns_probe_resolve(struct bs_store *rules, unsigned short port,
    const uint8_t *query, size_t size, unsigned budget, HANDLE cancel, struct dns_probe_result *result) {
    if (!result) return DNS_PROBE_INVALID;
    memset(result, 0, sizeof(*result));
    if (!rules || !port || !budget || budget > 1200 || !ddns_allowed(query, size)) return DNS_PROBE_INVALID;
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return DNS_PROBE_CANCELLED;
    struct bs_result resolved = bs_decide(rules, "example.com", 1, 1);
    if (!resolved.generation) return DNS_PROBE_INVALID;
    result->generation = resolved.generation; result->source = resolved.source;
    result->scope = (int)resolved.scope; result->action = (int)resolved.decision.action;
    if (dns_policy_respond(query, size, (enum dns_policy_action)resolved.decision.action,
            resolved.address, resolved.family == 4 ? 4u : resolved.family == 6 ? 16u : 0u,
            result->answer, sizeof(result->answer), &result->size)) return DNS_PROBE_OK;
    return exchange(port, query, size, budget, cancel, result);
}
