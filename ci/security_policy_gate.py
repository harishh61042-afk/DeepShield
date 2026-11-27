"""CI gate client. Reads credentials only from the process environment."""

import json
import os
import sys

import httpx


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Required environment variable is missing: {name}")
    return value


def main() -> int:
    base = required("DEPSHIELD_URL").rstrip("/") + "/api/v1"
    email = required("DEPSHIELD_EMAIL")
    password = required("DEPSHIELD_PASSWORD")
    project_id = required("DEPSHIELD_PROJECT_ID")
    scan_id = required("DEPSHIELD_SCAN_ID")
    with httpx.Client(base_url=base, follow_redirects=False, trust_env=False, timeout=20) as client:
        csrf_response = client.get("/auth/csrf")
        csrf_response.raise_for_status()
        csrf = csrf_response.json()["csrf_token"]
        login = client.post("/auth/login", headers={"X-CSRF-Token": csrf}, json={"email": email, "password": password})
        if login.status_code != 200:
            print("DepShield CI authentication failed; verify the configured action secrets.", file=sys.stderr)
            return 2
        csrf = login.json()["csrf_token"]
        scan = client.get(f"/scans/{scan_id}")
        if scan.status_code != 200 or scan.json().get("project_id") != project_id:
            print("The scan is unavailable to this account or does not belong to the configured project.", file=sys.stderr)
            return 2
        response = client.post(f"/scans/{scan_id}/policy/evaluate", headers={"X-CSRF-Token": csrf})
        if response.status_code != 200:
            print(f"DepShield policy evaluation failed with HTTP {response.status_code}.", file=sys.stderr)
            return 2
        result = response.json()
        print(json.dumps({"status": result["status"], "scan_id": scan_id,
                          "checks": result.get("checks", []), "failures": result.get("failures", []),
                          "warnings": result.get("warnings", [])}, indent=2))
        return 1 if result.get("status") == "FAIL" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        print(f"DepShield CI request failed ({type(exc).__name__}).", file=sys.stderr)
        raise SystemExit(2) from exc
