"""Extract the CWE-456 -> CWE-457 chain from an MSan log.

MSan built with -fsanitize-memory-track-origins reports WHERE the uninitialised value came
from ("was created by an allocation of 'buf' in the stack frame of ..."), which is the
missing-initialisation site, and SUMMARY gives the use site. Both links are therefore
EXECUTION-WITNESSED and localized - no patch heuristic and no dataflow needed.

Frames inside the sanitizer's own interceptors are skipped: they describe the instrumentation,
not the bug, exactly as the KASAN reporter frames had to be."""
import re

NOISE=re.compile(r"(compiler-rt/lib/(msan|sanitizer_common)|msan_interceptors|/usr/include/)")
LOC=re.compile(r"([a-zA-Z0-9_/.\-]+\.(?:c|cc|cpp|h)):(\d+)")
def parse(t):
    out={}
    m=re.search(r"was created by[^\n]*?(?:of '([^']+)')?[^\n]*\n((?:\s+#\d+[^\n]*\n){1,8})", t)
    if m:
        out["var"]=m.group(1)
        for line in m.group(2).splitlines():
            loc=LOC.search(line)
            if loc and not NOISE.search(loc.group(1)):
                fn=re.search(r"#\d+\s+0x\w+\s+in\s+([^\s/]+)", line)
                out["source"] = {
                    "file": loc.group(1),
                    "line": int(loc.group(2)),
                    "function": fn.group(1) if fn else None,
                }
                break
    s = re.search(
        r"SUMMARY: MemorySanitizer: \S+\s+"
        r"([a-zA-Z0-9_/.\-]+\.(?:c|cc|cpp|h)):(\d+)(?::\d+)?\s+in\s+(\S+)",
        t,
    )
    if s and not NOISE.search(s.group(1)):
        out["sink"]={"file":s.group(1),"line":int(s.group(2)),"function":s.group(3)}
    return out
