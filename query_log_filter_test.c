#include "query_log_filter.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
int main(void) {
    CHECK(qlf_matches(L"Ads.Example.Test",1,L"example",-1));
    CHECK(qlf_matches(L"Ads.Example.Test",1,L"ADS.",1));
    CHECK(!qlf_matches(L"Ads.Example.Test",1,L"ADS.",2));
    CHECK(!qlf_matches(L"Ads.Example.Test",1,L"other",-1));
    CHECK(qlf_matches(L"广告.example",0,L"广告",0));
    CHECK(qlf_matches(L"any",2,L"",2));
    CHECK(!qlf_matches(L"",0,L"x",-1));
    CHECK(!qlf_matches(NULL,0,L"",-1));
    puts("Local query-log filtering: action, case, Unicode, empty and absent host passed");
    return 0;
}
