#define _WIN32_WINNT 0x0A00
#include "wintun_probe_win32.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Read PE metadata only: even GetProcAddress can execute a forwarded DLL.
 * Do not enter the loader at all until M3 verifies the official artifact. */
struct pe_view {
    const unsigned char *bytes;
    DWORD size, sections;
    IMAGE_NT_HEADERS64 header;
};

static const unsigned char *rva(const struct pe_view *view, DWORD address, DWORD length) {
    if ((uint64_t)address + length <= view->header.OptionalHeader.SizeOfHeaders
            && (uint64_t)address + length <= view->size) return view->bytes + address;
    for (unsigned i = 0; i < view->header.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER section;
        memcpy(&section, view->bytes + view->sections + i * sizeof(section), sizeof(section));
        if (address < section.VirtualAddress) continue;
        uint64_t delta = (uint64_t)address - section.VirtualAddress;
        uint64_t offset = section.PointerToRawData + delta;
        if (delta + length <= section.SizeOfRawData && offset + length <= view->size)
            return view->bytes + (size_t)offset;
    }
    return NULL;
}

static bool exports_present(const unsigned char *bytes, DWORD size) {
    IMAGE_DOS_HEADER dos;
    if (size < sizeof(dos)) return false;
    memcpy(&dos, bytes, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0
            || (uint64_t)dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size) return false;
    struct pe_view view;
    view.bytes = bytes; view.size = size;
    memcpy(&view.header, bytes + dos.e_lfanew, sizeof(view.header));
    const IMAGE_FILE_HEADER *file = &view.header.FileHeader;
    if (view.header.Signature != IMAGE_NT_SIGNATURE || file->Machine != IMAGE_FILE_MACHINE_AMD64
            || !(file->Characteristics & IMAGE_FILE_DLL)
            || view.header.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
            || file->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)
            || !file->NumberOfSections || file->NumberOfSections > 96
            || view.header.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return false;
    uint64_t sections = (uint64_t)dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + file->SizeOfOptionalHeader;
    if (sections + file->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > size) return false;
    view.sections = (DWORD)sections;
    IMAGE_EXPORT_DIRECTORY exports;
    DWORD export_address = view.header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const unsigned char *directory = rva(&view, export_address, sizeof(exports));
    if (!export_address || !directory) return false;
    memcpy(&exports, directory, sizeof(exports));
    if (!exports.NumberOfNames || exports.NumberOfNames > 1024
            || !exports.NumberOfFunctions || exports.NumberOfFunctions > 65535) return false;
    const unsigned char *names = rva(&view, exports.AddressOfNames, exports.NumberOfNames * 4);
    const unsigned char *ordinals = rva(&view, exports.AddressOfNameOrdinals, exports.NumberOfNames * 2);
    const unsigned char *functions = rva(&view, exports.AddressOfFunctions, exports.NumberOfFunctions * 4);
    if (!names || !ordinals || !functions) return false;
    static const char *required[] = {
        "WintunOpenAdapter", "WintunCloseAdapter",
        "WintunCreateAdapter", "WintunGetAdapterLuid",
        "WintunStartSession", "WintunEndSession",
        "WintunGetReadWaitEvent", "WintunReceivePacket",
        "WintunReleaseReceivePacket", "WintunAllocateSendPacket",
        "WintunSendPacket", "WintunGetRunningDriverVersion"
    };
    for (unsigned i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        bool found = false;
        for (DWORD j = 0; j < exports.NumberOfNames; j++) {
            DWORD name_address, function_address; WORD ordinal;
            memcpy(&name_address, names + j * 4, 4);
            const unsigned char *name = rva(&view, name_address, (DWORD)strlen(required[i]) + 1);
            if (!name || memcmp(name, required[i], strlen(required[i]) + 1)) continue;
            memcpy(&ordinal, ordinals + j * 2, 2);
            if (ordinal >= exports.NumberOfFunctions) return false;
            memcpy(&function_address, functions + ordinal * 4, 4);
            found = function_address != 0;
            break;
        }
        if (!found) return false;
    }
    return true;
}

struct wintun_probe_result wintun_probe_local(void) {
    struct wintun_probe_result info = {WINTUN_PROBE_MISSING, 0, 0};
    wchar_t path[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (!length || length >= MAX_PATH) { info.last_error = ERROR_FILENAME_EXCED_RANGE; return info; }
    wchar_t *slash = wcsrchr(path, L'\\');
    if (!slash || (size_t)(slash - path) + 12 >= MAX_PATH) return info;
    wcscpy(slash + 1, L"wintun.dll");
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) { info.last_error = GetLastError(); return info; }
    BY_HANDLE_FILE_INFORMATION attributes; LARGE_INTEGER size;
    bool ok = GetFileInformationByHandle(file, &attributes)
            && !(attributes.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
            && GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= 16 * 1024 * 1024;
    unsigned char *bytes = ok ? (unsigned char *)malloc((size_t)size.QuadPart) : NULL;
    DWORD read = 0;
    if (ok) ok = bytes && ReadFile(file, bytes, (DWORD)size.QuadPart, &read, NULL)
            && read == (DWORD)size.QuadPart && exports_present(bytes, read);
    free(bytes); CloseHandle(file);
    info.status = ok ? WINTUN_PROBE_API_PRESENT_UNVERIFIED : WINTUN_PROBE_API_INCOMPLETE;
    info.last_error = ok ? 0 : ERROR_BAD_EXE_FORMAT;
    return info;
}
