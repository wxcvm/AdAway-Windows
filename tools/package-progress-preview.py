"""Assemble inspection release metadata without changing the production update feed."""
import hashlib
import os
from pathlib import Path
import shutil

root = Path(__file__).resolve().parent.parent
output = root / "release-assets"
output.mkdir(exist_ok=True)
files = {
    "adblock-preview-user-x64.exe": root / "dist-installer/adblock-preview-user-x64.exe",
    "adblock-preview-machine-x64.exe": root / "dist-installer/adblock-preview-machine-x64.exe",
    "adblock-webserver-win64.zip": root / "adblock-webserver-win64.zip",
}
for name, source in files.items():
    if not source.is_file() or source.stat().st_size < 100_000:
        raise ValueError("missing/invalid required preview artifact: " + name)
    shutil.copyfile(source, output / name)
digest = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in files}
script = (root / "tools/install-preview.ps1").read_text(encoding="utf-8")
for key, value in {
    "@@TAG@@": os.environ["PREVIEW_TAG"],
    "@@USER_SHA@@": digest["adblock-preview-user-x64.exe"],
    "@@MACHINE_SHA@@": digest["adblock-preview-machine-x64.exe"],
    "@@PORTABLE_SHA@@": digest["adblock-webserver-win64.zip"],
}.items():
    script = script.replace(key, value)
if "@@" in script:
    raise ValueError("unexpanded preview download identity")
(output / "install-preview.ps1").write_text(script, encoding="utf-8-sig")
shutil.copyfile(root / "docs/preview-installation.md", output / "INSTALLATION.md")
shutil.copyfile(root / "docs/m1-rule-loader-validation.md", output / "IMPLEMENTATION-STATUS.md")
(output / "SOURCE-COMMIT.txt").write_text(os.environ["GITHUB_SHA"] + "\n", encoding="utf-8")
checksums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
                    for p in sorted(output.iterdir()) if p.is_file() and p.name != "SHA256SUMS.txt")
(output / "SHA256SUMS.txt").write_text(checksums, encoding="utf-8")
print("Preview EXE installers, portable ZIP, pinned PowerShell installer and checksums prepared")

