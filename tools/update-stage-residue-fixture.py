"""Compile real updater control-flow sections with inert network/UI/process boundaries."""
import argparse
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument("source", type=Path)
p.add_argument("output", type=Path)
p.add_argument("--legacy-prefix-only", action="store_true")
args=p.parse_args()
src=args.source.read_text(encoding="utf-8")
start=src.index("static DWORD WINAPI apply_thread(")
portable=src.index("\nportable_fallback:", start)
prefix=src[start:portable]+"""
portable_fallback:
    reached_portable++;
    free(info);
    return 0;
}
"""
def function(name):
    at=src.index(name)
    return src[at:src.index("\n}\n",at)+3]
stage=""
if not args.legacy_prefix_only:
    at=src.index("    /* Reserve an exclusive stage only")
    end=src.index("    /*\n     * Extraction with a fallback chain",at)
    assert portable < src.index("int listing = ",portable) < src.index("if (listing == 0)",portable) < at
    assert "CreateDirectoryW(probe" not in prefix
    assert "GetLastError() == ERROR_ALREADY_EXISTS" not in src[at:end]
    stage=src[at:end]
template=(Path(__file__).with_name("update-stage-residue-fixture.c.in")).read_text(encoding="utf-8")
for key,value in {
    "@PREFIX@":prefix,
    "@STAGE@":stage,
    "@HAS_STAGE@":str(int(bool(stage))),
    "@FILE_IS_EXE@":function("static int file_is_exe("),
    "@TEMP_FILE@":function("static void update_temp_file("),
}.items():
    template=template.replace(key,value)
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(template,encoding="utf-8")
