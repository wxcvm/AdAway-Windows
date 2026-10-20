#ifndef ADBLOCK_UPDATE_FEED_H
#define ADBLOCK_UPDATE_FEED_H
#include <stddef.h>
struct release_pick {
    char tag[128], ver[64], build[32];
    char exe_url[1024], exe_sha[128], exe_api_url[512];
    char zip_url[1024], zip_sha[128], zip_api_url[512];
    int preview;
};
int update_version_cmp(const char *a, const char *b);
int update_feed_cmp(const struct release_pick *a, const struct release_pick *b);
int update_feed_manifest(const char *json, int preview, const char *tag, struct release_pick *out);
/* Read one complete release, independent of JSON key order. */
int update_feed_release(const char *json, unsigned index, int include_preview, struct release_pick *out);
#endif
