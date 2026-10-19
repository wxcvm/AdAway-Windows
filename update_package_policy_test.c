#include "update_package_policy.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    for (int exe=0;exe<2;exe++) for (int zip=0;zip<2;zip++) {
        assert(update_primary_package(exe,zip,1)==(zip ? 2 : 0));
        assert(update_alternate_package(exe,zip,1)==0);
        assert(update_primary_package(exe,zip,0)==(exe ? 1 : zip ? 2 : 0));
        assert(update_alternate_package(exe,zip,0)==(exe && zip ? 2 : 0));
    }
    puts("Automatic installer/ZIP fallback and explicit ZIP selection passed"); return 0;
}
