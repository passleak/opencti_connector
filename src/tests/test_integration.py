"""
Интеграционный тест против реального Passleak API.
Запуск: PASSLEAK_BASEURL=https://... PASSLEAK_API_KEY=plk_... python3 tests/test_integration.py
"""
import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from passleak.LeaksLoader import LeaksLoader

BASEURL = os.environ.get("PASSLEAK_BASEURL", "https://api.passleak.com/")
APIKEY  = os.environ.get("PASSLEAK_API_KEY", "")

if not APIKEY:
    print("ERROR: set PASSLEAK_API_KEY env var")
    sys.exit(1)

conf = {
    "baseurl": BASEURL,
    "apikey": APIKEY,
    "contimeout": 10,
    "readtimeout": 30,
    "retry": 2,
}

print(f"=== Connecting to {BASEURL} ===")
loader = LeaksLoader(conf)
loader.init_connection()
print("Connection OK\n")

print("=== Downloading leaks (empty state = all data) ===")
result = loader.download_leaks_data({})

if not result:
    print("No data returned (no approved domains or no events)")
    sys.exit(0)

for domain, data in result.items():
    items = data["items"]
    print(f"\nDomain: {domain}  ({len(items)} events, new_offset={data['new_offset']})")
    print(f"  First item fields: {list(items[0].keys())}")

    # Покажем первые 3 записи
    for i, rec in enumerate(items[:3]):
        stealer = rec.get("stealer_type") or "—"
        source  = rec.get("source") or "—"
        identity = rec.get("email") or rec.get("login") or "—"
        print(f"  [{i+1}] identity={identity!r}  source={source!r}  stealer={stealer!r}  event_time={rec.get('event_time')!r}")

    stealers = {r.get("stealer_type") for r in items if r.get("stealer_type")}
    sources  = {r.get("source") for r in items if r.get("source")}
    print(f"  Unique stealers: {stealers or '(none)'}")
    print(f"  Unique sources:  {sources}")
