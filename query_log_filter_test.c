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
    CHECK(qlf_matches_entry(L"v6.example",1,2,6,L"example",QLF_IPV6));
    CHECK(!qlf_matches_entry(L"v6.example",1,2,6,L"",QLF_IPV4));
    CHECK(qlf_matches_entry(L"::1",1,2,4,L"",QLF_IPV4)); /* Host never determines socket family. */
    CHECK(!qlf_matches_entry(L"::1",1,2,0,L"",QLF_IPV6));
    CHECK(qlf_matches_entry(L"v4.example",1,2,0,L"",QLF_FAMILY_UNKNOWN));
    CHECK(qlf_matches_entry(L"style.example",1,2,6,L"style",QLF_TYPE_BASE+2));
    CHECK(!qlf_matches_entry(L"style.example",0,2,6,L"",QLF_TYPE_BASE+2));
    CHECK(qlf_matches_entry(L"old.example",1,-1,0,L"",QLF_TYPE_UNKNOWN));
    CHECK(qlf_matches_entry(L"future.example",1,255,0,L"",QLF_TYPE_UNKNOWN));
    CHECK(!qlf_matches_entry(L"style.example",1,2,4,L"absent",QLF_TYPE_BASE+2));
    CHECK(qlf_filter_for_choice(4)==QLF_IPV4 && qlf_filter_for_choice(5)==QLF_IPV6);
    CHECK(qlf_filter_for_choice(9)==QLF_TYPE_BASE+2 && qlf_filter_for_choice(17)==QLF_TYPE_UNKNOWN);
    CHECK(qlf_filter_for_choice(-1)==-1 && qlf_filter_for_choice(99)==-1);
    puts("Local query-log filtering: action, case, Unicode, empty and absent host passed");
    return 0;
}
