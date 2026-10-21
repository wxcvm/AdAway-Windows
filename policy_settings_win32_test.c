#include "policy_settings_win32.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)

static struct policy_setting settings[POLICY_SETTINGS_COUNT] = {
    {"reply_images", "mode_images", 0}, {"reply_scripts", "mode_scripts", 3},
    {"reply_styles", "mode_styles", 3}, {"reply_fonts", "mode_fonts", 3},
    {"reply_media", "mode_media", 0}, {"reply_structures", "mode_struct", 0},
    {"reply_api", "mode_api", 1}, {"reply_telemetry", "mode_tele", 1},
    {"reply_config", "mode_conf", 1}, {"reply_ws_sse", "mode_ws", 1}
};
static void read_file(const wchar_t *path, char *bytes, size_t cap) {
    FILE *file = _wfopen(path, L"rb"); CHECK(file);
    size_t count = fread(bytes, 1, cap - 1, file); bytes[count] = 0;
    CHECK(!ferror(file)); CHECK(fclose(file) == 0);
}
static void unchanged(const wchar_t *target, const char *expected) {
    char bytes[4096]; read_file(target, bytes, sizeof(bytes)); CHECK(!strcmp(bytes,expected));
}
int main(void) {
    wchar_t temp[MAX_PATH], parent[MAX_PATH], directory[MAX_PATH], target[MAX_PATH], lock_path[MAX_PATH];
    CHECK(GetTempPathW(MAX_PATH,temp)); CHECK(GetTempFileNameW(temp,L"pft",0,parent));
    CHECK(DeleteFileW(parent)); CHECK(CreateDirectoryW(parent,NULL));
    CHECK(swprintf(directory,MAX_PATH,L"%ls\\策略 文件夹",parent)>0); CHECK(CreateDirectoryW(directory,NULL));
    CHECK(swprintf(target,MAX_PATH,L"%ls\\block_config.json",directory)>0);
    CHECK(swprintf(lock_path,MAX_PATH,L"%ls\\.policy-settings.lock",directory)>0);
    CHECK(policy_settings_save(directory,settings,POLICY_SETTINGS_COUNT));
    char before[4096],after[4096]; read_file(target,before,sizeof(before));
    CHECK(strstr(before,"\"reply_scripts\": true,")); CHECK(strstr(before,"\"mode_scripts\": 3,"));
    CHECK(strstr(before,"\"mode_ws\": 1\n}\n"));
    HANDLE reader = CreateFileW(target,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    CHECK(reader!=INVALID_HANDLE_VALUE);
    settings[0].mode=2;
    CHECK(!policy_settings_save(directory,settings,POLICY_SETTINGS_COUNT));
    unchanged(target,before); CHECK(CloseHandle(reader));
    HANDLE lock = CreateFileW(lock_path,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    CHECK(lock!=INVALID_HANDLE_VALUE);
    CHECK(!policy_settings_save(directory,settings,POLICY_SETTINGS_COUNT));
    unchanged(target,before); CHECK(CloseHandle(lock));
    CHECK(SetFileAttributesW(target,FILE_ATTRIBUTE_READONLY));
    CHECK(!policy_settings_save(directory,settings,POLICY_SETTINGS_COUNT));
    unchanged(target,before); CHECK(SetFileAttributesW(target,FILE_ATTRIBUTE_NORMAL));
    for(int mode=0;mode<=3;mode++) {
        settings[0].mode=mode; CHECK(policy_settings_save(directory,settings,POLICY_SETTINGS_COUNT));
        read_file(target,after,sizeof(after));
        char expected[80]; CHECK(snprintf(expected,sizeof(expected),"\"mode_images\": %d,",mode)>0);
        CHECK(strstr(after,expected)); CHECK(strstr(after,mode==2?"\"reply_images\": false,":"\"reply_images\": true,"));
    }
    read_file(target,before,sizeof(before));
    settings[0].mode=4; CHECK(!policy_settings_save(directory,settings,POLICY_SETTINGS_COUNT)); unchanged(target,before);
    settings[0].mode=0;
    const char *original_key=settings[0].reply_key;
    settings[0].reply_key="bad\"\ninjection";
    CHECK(!policy_settings_save(directory,settings,POLICY_SETTINGS_COUNT)); unchanged(target,before);
    settings[0].reply_key=settings[1].mode_key;
    CHECK(!policy_settings_save(directory,settings,POLICY_SETTINGS_COUNT)); unchanged(target,before);
    settings[0].reply_key=original_key;
    CHECK(!policy_settings_save(directory,settings,POLICY_SETTINGS_COUNT-1)); unchanged(target,before);
    CHECK(!policy_settings_save(directory,NULL,POLICY_SETTINGS_COUNT)); unchanged(target,before);
    wchar_t pattern[MAX_PATH]; CHECK(swprintf(pattern,MAX_PATH,L"%ls\\pol*.tmp",directory)>0);
    WIN32_FIND_DATAW found; HANDLE entries=FindFirstFileW(pattern,&found);
    CHECK(entries==INVALID_HANDLE_VALUE && GetLastError()==ERROR_FILE_NOT_FOUND);
    CHECK(DeleteFileW(target)); CHECK(DeleteFileW(lock_path)); CHECK(RemoveDirectoryW(directory)); CHECK(RemoveDirectoryW(parent));
    puts("Policy settings: Unicode paths, all four legacy modes, atomic locked/read-only rollback, retry and validation passed");
    return 0;
}
