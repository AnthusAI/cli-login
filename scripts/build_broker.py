"""Build the broker's Lambda zip deterministically and print its sha256, so the same source gives the same key.

    python scripts/build_broker.py [out.zip]

Upload it under a key named by the sha256, then deploy infra/broker.yaml with that CodeKey.
"""

import hashlib
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "cli_login"


def build(out: Path) -> str:
    files = sorted(p for p in PACKAGE.rglob("*.py") if not p.name.endswith("_test.py") and p.name not in ("testing.py", "testing_processes.py"))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            info = zipfile.ZipInfo(str(path.relative_to(ROOT / "src")), date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    return hashlib.sha256(out.read_bytes()).hexdigest()


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "broker.zip")
    digest = build(target)
    print(f"{target}\nsha256 {digest}\nCodeKey cli-login/broker-{digest}.zip")
