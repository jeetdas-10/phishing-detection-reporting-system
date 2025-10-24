# phishdetect/domain_utils.py
import os
import tldextract

def registered_domain(u: str) -> str:
    ext = tldextract.extract(str(u))
    reg = getattr(ext, "top_domain_under_public_suffix", "") or ""
    if not reg:
        reg = ".".join([p for p in [ext.domain, ext.suffix] if p])
    return (reg or "unknown").lower()

def load_allowlist(path: str | None):
    if not path:
        return set()
    if not os.path.exists(path):
        raise SystemExit(f"❌ Allowlist file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        items = [ln.strip().lower() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    return set(items)
