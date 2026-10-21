/* Actual bounded desktop response/page parser used by the loopback fixture. */
#include "query_log_page.h"
#include <stdio.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
int main(int argc, char **argv) {
    static char response[192 * 1024];
    struct qlp_request request;
    struct mg_str body;
    uint64_t offset = 0;
    if (argc != 2 && argc != 4) return 1;
    memset(&request, 0, sizeof(request));
    if (!qlp_decimal_digits(argv[1], strlen(argv[1]), &offset) || offset > QLP_MAX_TOTAL) return 1;
    request.offset = (uint32_t)offset;
    if (argc == 4) {
        if (strlen(argv[2]) >= sizeof(request.generation) || strlen(argv[3]) >= sizeof(request.anchor)) return 1;
        memcpy(request.generation, argv[2], strlen(argv[2]) + 1);
        memcpy(request.anchor, argv[3], strlen(argv[3]) + 1);
    }
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) < 0) return 1;
#endif
    size_t length = fread(response, 1, sizeof(response), stdin);
    if (ferror(stdin) || length == sizeof(response) || !dashboard_response_body(response, length, &body)) return 2;
    mg_log_set(MG_LL_NONE);
    struct qlp_page *page = (struct qlp_page *)calloc(1, sizeof(*page));
    if (!page) return 1;
    if (!qlp_parse(body, &request, page)) { free(page); return 2; }
    printf("%u,%u,%u,%u,%d,%s,%s\n", page->offset, page->returned, page->next_offset,
           page->total, page->has_more ? 1 : 0, page->generation, page->anchor);
    for (uint32_t i = 0; i < page->returned; i++) puts(page->rows[i].host);
    free(page);
    return 0;
}
