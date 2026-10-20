#include "update_feed.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    struct release_pick stable, preview, installed = {0}, bad;
    char fixture[8192];
    assert(argc == 2);
    FILE *f=fopen(argv[1],"rb"); assert(f);
    size_t n=fread(fixture,1,sizeof(fixture)-1,f); fixture[n]=0; fclose(f);
    assert(update_feed_manifest(fixture,0,NULL,&stable));
    assert(!strcmp(stable.ver,"1.75"));
    const char *manifest="{\"version\":\"1.79\",\"tag\":\"progress-win-20261020.4\",\"channel\":\"preview\",\"build\":\"39410500291\","
        "\"exe_url\":\"https://github.com/wxcvm/AdAway-Windows/releases/download/progress-win-20261020.4/adblock-webserver-setup.exe\","
        "\"exe_sha256\":\"sha256:1177114d9bf58f070579b9da2ad373931010f701bb1f1432941cb15ad2526da9\"}";
    assert(update_feed_manifest(manifest,1,NULL,&preview));
    assert(!update_feed_manifest(manifest,0,NULL,&bad));
    assert(!update_feed_manifest(manifest,1,"progress-win-20261020.3",&bad));
    assert(update_feed_cmp(&preview,&stable)>0);
    strcpy(installed.ver,"1.79"); strcpy(installed.build,"39410500290");
    assert(update_feed_cmp(&preview,&installed)>0);
    assert(update_feed_cmp(&installed,&preview)<0);
    installed=preview;
    assert(update_feed_cmp(&preview,&installed)==0);
    strcpy(installed.ver,"1.80"); assert(update_feed_cmp(&preview,&installed)<0);
    const char *releases="[{\"prerelease\":true,\"tag_name\":\"progress-win-20261020.4\",\"draft\":false},"
        "{\"prerelease\":true,\"draft\":true,\"tag_name\":\"progress-win-20261020.99\"},"
        "{\"draft\":false,\"tag_name\":\"win11-preview\",\"prerelease\":true}]";
    assert(update_feed_release(releases,0,0,&bad)==0);
    assert(update_feed_release(releases,0,1,&bad)==2);
    assert(update_feed_release(releases,1,1,&bad)==0);
    assert(update_feed_release(releases,2,1,&bad)==0);
    assert(update_feed_release(releases,3,1,&bad)==-1);
    assert(!update_feed_manifest("{}",1,NULL,&bad));
    assert(!update_feed_manifest("{",1,NULL,&bad));
    puts("Update channel: stable isolation, opt-in preview, build order, immutable URLs and malformed input passed");
    return 0;
}
