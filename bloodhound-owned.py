#!/usr/bin/env python3
r"""
bloodhound-owned.py - Mark BloodHound Community Edition users as 'owned'.

Feed it a credentials file (one `user:password` per line). For each username
it searches the BloodHound graph, resolves the matching User node, and creates
an Owned selector under the built-in "Owned" asset-group-tag (the current BH CE
model -- the legacy /api/v2/asset-groups selectors no longer drive the
Tag_Owned skull label).

Authentication uses the BloodHound CE API token scheme (token ID + token key,
HMAC-SHA256 signed requests). Create a token in the BloodHound UI:
    My Profile -> API Key Management -> Create Token

Examples:
    python3 bloodhound-owned.py -f creds.txt \
        --url http://localhost:8080 \
        --token-id  <TOKEN_ID> \
        --token-key <TOKEN_KEY>

    # creds via stdin
    cat creds.txt | python3 bloodhound-owned.py -f - --token-id ... --token-key ...

    # token from env (BHE_TOKEN_ID / BHE_TOKEN_KEY)
    python3 bloodhound-owned.py -f creds.txt

Credential file format (password is ignored, only the username matters):
    administrator:Summer2024!
    CORP\jsmith:Hunter2
    bob@corp.local:passw0rd
    # lines starting with # are skipped
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime
from urllib import error, request


class BHEClient:
    """Minimal BloodHound CE API client with HMAC token signing."""

    def __init__(self, base_url, token_id, token_key, verify_tls=True):
        self.base_url = base_url.rstrip("/")
        self.token_id = token_id
        self.token_key = token_key
        self.verify_tls = verify_tls

    def _sign(self, method, uri, body_bytes):
        # Per BloodHound CE docs: chained HMAC over method+uri, then the
        # RFC3339 datetime truncated to the hour, then the request body.
        digester = hmac.new(self.token_key.encode(), None, hashlib.sha256)
        digester.update(f"{method}{uri}".encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        now = datetime.now().astimezone().isoformat("T")
        digester.update(now[:13].encode())  # YYYY-MM-DDTHH

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        if body_bytes:
            digester.update(body_bytes)

        return now, base64.b64encode(digester.digest()).decode()

    def request(self, method, uri, body=None):
        body_bytes = json.dumps(body).encode() if body is not None else b""
        req_date, signature = self._sign(method, uri, body_bytes)

        req = request.Request(self.base_url + uri, method=method)
        req.add_header("Authorization", f"bhesignature {self.token_id}")
        req.add_header("RequestDate", req_date)
        req.add_header("Signature", signature)
        req.add_header("Content-Type", "application/json")

        ctx = None
        if self.base_url.startswith("https") and not self.verify_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        data = body_bytes if body is not None else None
        try:
            with request.urlopen(req, data=data, context=ctx) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"error": raw.decode(errors="replace")}

    # --- high-level helpers -------------------------------------------------

    def find_owned_tag_id(self):
        """Resolve the 'Owned' asset-group-TAG id (current BH CE model).

        Owned marking moved from the legacy /api/v2/asset-groups selectors
        (which no longer drive the Tag_Owned label) to the asset-group-tags
        system. Return the id of the tag named 'Owned'.
        """
        status, body = self.request("GET", "/api/v2/asset-group-tags")
        if status != 200:
            raise RuntimeError(f"list asset-group-tags failed: {status} {body}")
        tags = body.get("data", {}).get("tags", [])
        for t in tags:
            if str(t.get("name", "")).lower() == "owned":
                return t["id"]
        raise RuntimeError("no asset-group-tag named 'Owned' found")

    def cypher(self, query):
        status, body = self.request(
            "POST", "/api/v2/graphs/cypher", {"query": query}
        )
        if status != 200:
            return {}
        return body.get("data", {}) or {}

    def count_owned(self):
        """Count owned User nodes the current BloodHound CE way.

        BH CE marks owned with the node KIND label `Tag_Owned` (queryable in
        cypher). NOTE: `isOwnedObject` in node JSON is a computed API display
        field, NOT a stored graph property -- `WHERE u.isOwnedObject = true`
        always returns 0. Match on the `Tag_Owned` label instead. Owned is
        also not in `system_tags` in current BH CE.

        Scalar RETURNs don't render in the Explore UI but come back as
        `literals` over the API.
        """
        data = self.cypher("MATCH (u:User) WHERE u:Tag_Owned RETURN count(u)")
        for lit in data.get("literals", []) or []:
            return lit.get("value")
        return None

    def resolve_user(self, bare):
        """Find a User node by sAMAccountName (login name) or display name.

        BloodHound stores the display name in `name` (e.g.
        ANTONIO RODRIGUEZ GALLEGO@DOMAIN) while cred files carry the
        sAMAccountName (e.g. anroga), so match on `samaccountname` first.
        Returns (name, objectid) or (None, None).
        """
        esc = bare.lower().replace("\\", "\\\\").replace("'", "\\'")
        q = (
            "MATCH (u:User) WHERE toLower(u.samaccountname)='%s' "
            "OR toLower(u.name)='%s' OR toLower(u.name) STARTS WITH '%s@' "
            "RETURN u LIMIT 1" % (esc, esc, esc)
        )
        nodes = self.cypher(q).get("nodes", {}) or {}
        for node in nodes.values():
            return node.get("label"), node.get("objectId")
        return None, None

    def add_owned(self, tag_id, name, sid):
        """Create an Owned selector for one object via the asset-group-tags
        API. Seed type 1 = ObjectID (SID). Returns (status, body)."""
        body = {"name": name, "seeds": [{"type": 1, "value": sid}]}
        return self.request(
            "POST", f"/api/v2/asset-group-tags/{tag_id}/selectors", body
        )

    def run_analysis(self):
        """Kick a re-analysis so the Owned tag's selectors resolve onto their
        nodes: BH CE stamps them with kind `Tag_Owned` (the skull glyph).
        Returns HTTP status (202 = queued)."""
        status, _ = self.request("PUT", "/api/v2/analysis")
        return status

    def datapipe_status(self):
        """Return current datapipe status string (e.g. 'idle', 'analyzing',
        'ingesting') or None. 'idle' == analysis finished."""
        status, body = self.request("GET", "/api/v2/datapipe/status")
        if status != 200:
            return None
        return (body.get("data", {}) or {}).get("status")

    def wait_for_analysis(self, timeout=600, interval=5):
        """Block until the datapipe returns to 'idle' (analysis done) or the
        timeout elapses. Returns True if it went idle, False on timeout."""
        deadline = time.time() + timeout
        # give the queued job a moment to flip the status off 'idle' first
        time.sleep(interval)
        while time.time() < deadline:
            st = self.datapipe_status()
            if st == "idle":
                return True
            time.sleep(interval)
        return False


def normalize_username(raw):
    """Return (search_term, bare_name) from any of user, DOM\\user, user@dom."""
    raw = raw.strip()
    bare = raw
    if "\\" in bare:
        bare = bare.split("\\", 1)[1]
    if "@" in bare:
        bare = bare.split("@", 1)[0]
    return raw, bare


def parse_creds(path):
    fh = sys.stdin if path == "-" else open(path, encoding="utf-8", errors="replace")
    try:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            user = line.split(":", 1)[0] if ":" in line else line
            if user:
                yield user
    finally:
        if fh is not sys.stdin:
            fh.close()


def main():
    p = argparse.ArgumentParser(description="Mark BloodHound CE users as owned")
    p.add_argument("-f", "--file", required=True,
                   help="creds file (user:password per line, '-' for stdin)")
    p.add_argument("--url", default=os.environ.get("BHE_URL", "http://localhost:8080"),
                   help="BloodHound CE base URL (default: http://localhost:8080)")
    p.add_argument("--token-id", default=os.environ.get("BHE_TOKEN_ID"),
                   help="API token ID (or env BHE_TOKEN_ID)")
    p.add_argument("--token-key", default=os.environ.get("BHE_TOKEN_KEY"),
                   help="API token key (or env BHE_TOKEN_KEY)")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="skip TLS verification")
    p.add_argument("--dry-run", action="store_true",
                   help="resolve users but do not mark owned")
    p.add_argument("--no-analysis", action="store_true",
                   help="do not trigger re-analysis after marking")
    p.add_argument("--timeout", type=int, default=600,
                   help="max seconds to wait for analysis to finish (default 600)")
    args = p.parse_args()

    if not args.token_id or not args.token_key:
        p.error("token id/key required (--token-id/--token-key or env)")

    client = BHEClient(args.url, args.token_id, args.token_key,
                       verify_tls=not args.insecure)

    try:
        tag_id = client.find_owned_tag_id()
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Owned asset-group-tag id = {tag_id}")

    seen = set()
    owned = notfound = 0
    for user in parse_creds(args.file):
        term, bare = normalize_username(user)
        if bare.lower() in seen:
            continue
        seen.add(bare.lower())

        name, sid = client.resolve_user(bare)
        if not sid:
            print(f"[-] not found: {user}")
            notfound += 1
            continue

        if args.dry_run:
            print(f"[=] would own: {name} ({sid})")
            owned += 1
            continue

        # selector name must be unique per tag; SID guarantees uniqueness and
        # keeps re-runs from colliding on duplicate names.
        selector = f"pentest_{sid}"
        status, body = client.add_owned(tag_id, selector, sid)
        if status in (200, 201):
            print(f"[+] owned: {name} ({sid})")
            owned += 1
        else:
            print(f"[!] failed {name}: {status} {body}")

    print(f"\n[*] done. owned={owned} notfound={notfound}")

    analysis_done = True
    if owned and not args.dry_run and not args.no_analysis:
        st = client.run_analysis()
        if st == 202:
            print("[*] re-analysis queued; waiting for it to finish...")
            analysis_done = client.wait_for_analysis(timeout=args.timeout)
            if analysis_done:
                print("[*] analysis finished")
            else:
                print(f"[!] analysis still running after {args.timeout}s; "
                      "owned count below may be stale")
        else:
            print(f"[!] analysis trigger returned {st}")

    if not args.dry_run:
        total = client.count_owned()
        if total is not None:
            print(f"[*] owned User nodes now in graph: {total}")
            print("    verify:  MATCH (u:Tag_Owned) RETURN u")
        elif not analysis_done:
            print("[!] owned count unavailable; analysis not finished yet")
        else:
            print("[!] could not read owned count")


if __name__ == "__main__":
    main()
