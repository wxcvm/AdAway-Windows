#ifndef ADBLOCK_UPDATE_PACKAGE_POLICY_H
#define ADBLOCK_UPDATE_PACKAGE_POLICY_H
/* 0 absent, 1 installer, 2 ZIP. Explicit ZIP mode must not fetch an EXE first. */
static inline int update_primary_package(int has_exe,int has_zip,int portable) {
    if (portable) return has_zip ? 2 : 0;
    return has_exe ? 1 : has_zip ? 2 : 0;
}
static inline int update_alternate_package(int has_exe,int has_zip,int portable) {
    return !portable && has_exe && has_zip ? 2 : 0;
}
#endif
