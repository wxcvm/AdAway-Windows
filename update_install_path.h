#ifndef ADBLOCK_UPDATE_INSTALL_PATH_H
#define ADBLOCK_UPDATE_INSTALL_PATH_H

#include <stddef.h>
#include <wchar.h>

/* Compare complete install directory paths, never drive letter alone.
 * Accept slash/backslash variants and a trailing separator on non-root paths.
 * Do not equate C: (drive-relative) with C:\ (drive root).
 * Preserve Unicode code units; fold ASCII only, like the legacy comparator. */
static int update_install_path_equal(const wchar_t *left, const wchar_t *right) {
    if (!left || !right || !*left || !*right) return 0;
    size_t lhs = wcslen(left), rhs = wcslen(right);
    while (lhs > 3 && (left[lhs - 1] == L'\\' || left[lhs - 1] == L'/')) --lhs;
    while (rhs > 3 && (right[rhs - 1] == L'\\' || right[rhs - 1] == L'/')) --rhs;
    if (lhs != rhs) return 0;
    for (size_t i = 0; i < lhs; ++i) {
        wchar_t a = left[i] == L'/' ? L'\\' : left[i];
        wchar_t b = right[i] == L'/' ? L'\\' : right[i];
        if (a >= L'a' && a <= L'z') a -= L'a' - L'A';
        if (b >= L'a' && b <= L'z') b -= L'a' - L'A';
        if (a != b) return 0;
    }
    return 1;
}

#endif
