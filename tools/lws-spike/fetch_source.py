"""Fetch only SHA-verified prototype files from a fixed Android commit; never production core."""

import hashlib, json, pathlib, urllib.request, argparse

HERE = pathlib.Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument("directory")
a = p.parse_args()
out = pathlib.Path(a.directory).resolve()
out.mkdir(parents=True, exist_ok=True)
lock = json.loads((HERE / "source.json").read_text(encoding="utf8"))
for name, digest in lock["files"].items():
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise RuntimeError("Unsafe prototype manifest path")
    target = out / path
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        raw = urllib.request.urlopen(
            f"https://raw.githubusercontent.com/{lock['repository']}/{lock['commit']}/tools/lws-spike/{name}",
            timeout=60,
        ).read()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError("Downloaded prototype digest mismatch: " + name)
        target.write_bytes(raw)
    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise RuntimeError("Changed prototype cache; preserve edits: " + name)
print(
    json.dumps(
        {
            "commit": lock["commit"],
            "tree": lock["tree"],
            "files": len(lock["files"]),
            "directory": str(out),
        },
        indent=2,
    )
)
