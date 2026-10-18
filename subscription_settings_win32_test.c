#include "subscription_settings_win32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static void read_file(const wchar_t *path, char *bytes, size_t cap) {
    FILE *file = _wfopen(path, L"rb"); CHECK(file);
    size_t count = fread(bytes, 1, cap - 1, file); bytes[count] = 0;
    CHECK(!ferror(file)); CHECK(fclose(file) == 0);
}
int main(void) {
    wchar_t temporary[MAX_PATH], directory[MAX_PATH], target[MAX_PATH], status_path[MAX_PATH], lock_path[MAX_PATH];
    CHECK(GetTempPathW(MAX_PATH, temporary)); CHECK(GetTempFileNameW(temporary, L"asc", 0, directory));
    CHECK(DeleteFileW(directory)); CHECK(CreateDirectoryW(directory, NULL));
    CHECK(swprintf(target, MAX_PATH, L"%ls\\subscription_urls.txt", directory) > 0);
    CHECK(swprintf(status_path, MAX_PATH, L"%ls\\subscription_status.txt", directory) > 0);
    CHECK(swprintf(lock_path, MAX_PATH, L"%ls\\.subscription-settings.lock", directory) > 0);
    wchar_t urls[2][SUBSCRIPTION_URL_CAPACITY] = {L"https://example.test/One", L"https://example.test/规则"};
    const wchar_t status[2][SUBSCRIPTION_STATUS_CAPACITY] = {L"saved", L"保留旧规则"};
    CHECK(subscription_settings_save_urls(directory, (const wchar_t (*)[SUBSCRIPTION_URL_CAPACITY])urls, 2));
    char old[1024], bytes[1024]; read_file(target, old, sizeof(old));
    CHECK(strstr(old, "https://example.test/One\n")); CHECK(strstr(old, "规则\n"));
    HANDLE reader = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(reader != INVALID_HANDLE_VALUE);
    CHECK(!subscription_settings_save_urls(directory, (const wchar_t (*)[SUBSCRIPTION_URL_CAPACITY])urls, 1));
    read_file(target, bytes, sizeof(bytes)); CHECK(strcmp(old, bytes) == 0); CHECK(CloseHandle(reader));
    HANDLE lock = CreateFileW(lock_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(lock != INVALID_HANDLE_VALUE);
    CHECK(!subscription_settings_save_urls(directory, (const wchar_t (*)[SUBSCRIPTION_URL_CAPACITY])urls, 0));
    CHECK(CloseHandle(lock)); read_file(target, bytes, sizeof(bytes)); CHECK(strcmp(old, bytes) == 0);
    wcscpy(urls[1], L"https://example.test/new\nhttps://injected.test");
    CHECK(!subscription_settings_save_urls(directory, (const wchar_t (*)[SUBSCRIPTION_URL_CAPACITY])urls, 2));
    read_file(target, bytes, sizeof(bytes)); CHECK(strcmp(old, bytes) == 0);
    wcscpy(urls[1], L"https://example.test/规则");
    CHECK(subscription_settings_save_status(directory, (const wchar_t (*)[SUBSCRIPTION_URL_CAPACITY])urls, status, 2));
    read_file(status_path, bytes, sizeof(bytes)); CHECK(strstr(bytes, "规则\t保留旧规则\n"));
    CHECK(subscription_settings_save_urls(directory, (const wchar_t (*)[SUBSCRIPTION_URL_CAPACITY])urls, 0));
    read_file(target, bytes, sizeof(bytes)); CHECK(!strstr(bytes, "https://"));
    CHECK(DeleteFileW(target)); CHECK(DeleteFileW(status_path)); CHECK(DeleteFileW(lock_path)); CHECK(RemoveDirectoryW(directory));
    puts("Subscription settings: UTF-8, lock/replace rollback, injection rejection and empty save passed");
    return 0;
}
