# Licensing and third-party components

This repository develops the Windows client of [wxcvm/AdAway](https://github.com/wxcvm/AdAway), which derives from [AdAway/AdAway](https://github.com/AdAway/AdAway).

## Project and upstream code

The maintainer's own original contributions are offered under **GNU GPL version 3 or, at your option, any later version** (GPL-3.0-or-later). See [LICENSE.md](LICENSE.md) for the GPLv3 text. Files copied or fetched from the AdAway project remain under their original copyright and license notices. Do not remove original authors' attribution.

This repository's build retrieves the Android repository's C service and bundled Mongoose files from a **pinned commit** using `fetch-upstream.sh`; the source is not necessarily checked in here. The build provenance matters for any released Windows binary.

## Third-party components directly relevant to the Windows build

| Component | Source | License / notice |
| --- | --- | --- |
| AdAway-derived service code | https://github.com/AdAway/AdAway and https://github.com/wxcvm/AdAway | GPL-3.0-or-later; retain contributors' copyright notices |
| Mongoose (bundled in fetched C core) | https://github.com/cesanta/mongoose | **GPL-2.0-only OR commercial**, per `webserver/jni/mongoose/LICENSE` and `mongoose.h` in the Android repository |
| OpenSSL 3.5.9 (built from pinned official source) | https://github.com/openssl/openssl/tree/openssl-3.5.9 | **Apache License 2.0**; see https://github.com/openssl/openssl/blob/openssl-3.5.9/LICENSE.txt |

Other runtime DLLs and build-time components may require additional notices. This table is **not** a complete Software Bill of Materials (SBOM). Verify packaged files and their applicable notices per release.

## Outstanding distribution compatibility risk

`build.sh` compiles `$JNI/mongoose/mongoose.c` together with the GPLv3-derived C service code into `webserver.exe`. GPL-2.0-only and GPLv3 are normally incompatible for a single combined derivative work absent separately granted permission or a qualifying license exception. The upstream Mongoose dual-license statement does **not** automatically grant a commercial license. **Adding LICENSE.md or this notice does not cure the possible conflict.** Confirm appropriate rights or migrate to a GPLv3-compatible alternative before distributing affected binaries.

Before publishing a release, provide its corresponding source code, modification notices, build instructions, and applicable third-party license/notice texts. Review license compatibility again against the exact source revision and build artifact.
