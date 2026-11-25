# Licensing and third-party components

This repository develops the Windows client of [wxcvm/AdAway](https://github.com/wxcvm/AdAway), which derives from [AdAway/AdAway](https://github.com/AdAway/AdAway).

## Project and upstream code

The AdAway upstream project declares GPL-3.0-or-later; see its [license text](https://github.com/wxcvm/AdAway/blob/e94cb62d36fd1ea7005e6fac399b8d6bc8a2fd15/LICENSE.md). The independent licensing terms of maintainer-owned Windows additions remain to be confirmed by their rights holders. This inventory does not grant a new license. Files copied or fetched from the AdAway project remain under their original copyright and license notices. Do not remove original authors' attribution.

This repository's build retrieves the Android repository's C service and bundled Mongoose files from **separate pinned commits** using `fetch-upstream.sh`; the source is not necessarily checked in here. At review (2026-11-25), the core pin is `4470606366e614abdb308fdfe94734d28167439c` and the Mongoose pin is `b885198a34d95a9e30f1534ba11a3a2a01d961b7` (7.24). The actual compiled service also includes Windows-owned overlays. Recheck both pins for every release.

## Third-party components directly relevant to the Windows build

| Component | Source | License / notice |
| --- | --- | --- |
| AdAway-derived service code | https://github.com/AdAway/AdAway and https://github.com/wxcvm/AdAway | GPL-3.0-or-later; retain contributors' copyright notices |
| Mongoose (bundled in fetched C core) | https://github.com/cesanta/mongoose | **GPL-2.0-only OR commercial**, per `webserver/jni/mongoose/LICENSE` and `mongoose.h` in the Android repository |
| OpenSSL 3.5.9 (built from pinned official source) | https://github.com/openssl/openssl/tree/openssl-3.5.9 | **Apache License 2.0**; see https://github.com/openssl/openssl/blob/openssl-3.5.9/LICENSE.txt |

Other runtime DLLs and build-time components may require additional notices. This table is **not** a complete Software Bill of Materials (SBOM). Verify packaged files and their applicable notices per release.

## Outstanding distribution compatibility risk

`build.sh` compiles `$JNI/mongoose/mongoose.c` together with the GPLv3-derived C service code into `webserver.exe`. GPL-2.0-only and GPLv3 are normally incompatible for a single combined derivative work absent separately granted permission or a qualifying license exception. The upstream Mongoose dual-license statement does **not** automatically grant a commercial license. **This attribution notice does not cure the possible conflict.** Confirm appropriate rights or migrate to a GPLv3-compatible alternative before distributing affected binaries.

Before publishing a release, provide its corresponding source code, modification notices, build instructions, and applicable third-party license/notice texts. Review license compatibility again against the exact source revision and build artifact.
