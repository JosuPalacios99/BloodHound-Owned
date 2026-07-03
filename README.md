# BloodHound-Owned

Bulk-mark BloodHound Community Edition users as **Owned** (the skull glyph) from a
credentials/username list.

Feed it a file of `user:password` lines (typically cracked hashes output). For each
entry it resolves the matching `User` node in the BloodHound graph and creates an
**Owned** selector via the asset-group-tags API, then triggers a re-analysis so the
nodes get the `Tag_Owned` label.

> Useful after a password-cracking pass to instantly light up every compromised
> account in BloodHound, so attack-path queries (`Shortest paths from Owned`, etc.)
> reflect real footholds.

## Requirements

- Python 3.6+ (standard library only — no pip installs)
- A BloodHound CE instance you can reach
- A BloodHound CE API token: `Settings → Administration → API tokens → Create token`

## Install

```bash
git clone https://github.com/JosuPalacios99/BloodHound-Owned.git
cd BloodHound-Owned
chmod +x bloodhound-owned.py
```

## Usage

```bash
python3 bloodhound-owned.py -f creds.txt \
    --url http://localhost:8080 \
    --token-id  <TOKEN_ID> \
    --token-key <TOKEN_KEY>
```

Token can also come from the environment:

```bash
export BHE_URL=http://localhost:8080
export BHE_TOKEN_ID=<TOKEN_ID>
export BHE_TOKEN_KEY=<TOKEN_KEY>
python3 bloodhound-owned.py -f creds.txt
```

Creds via stdin:

```bash
cat creds.txt | python3 bloodhound-owned.py -f -
```

### Options

| Flag | Description |
|------|-------------|
| `-f, --file` | Credentials file (`user:password` per line, `-` for stdin). **Required.** |
| `--url` | BloodHound CE base URL (default `http://localhost:8080`, or `BHE_URL`). |
| `--token-id` | API token ID (or `BHE_TOKEN_ID`). |
| `--token-key` | API token key (or `BHE_TOKEN_KEY`). |
| `-k, --insecure` | Skip TLS verification (self-signed HTTPS). |
| `--dry-run` | Resolve users and report matches, but mark nothing. |
| `--no-analysis` | Do not trigger re-analysis after marking. |
| `--timeout` | Max seconds to wait for analysis to finish (default 600). |

Run `--dry-run` first to confirm your usernames resolve against the graph before
committing changes.

## Input format

One entry per line. The **password is ignored** — only the username is used. All of
these are accepted; the domain is stripped down to the sAMAccountName for matching:

```
administrator:Summer2024!
CORP\jsmith:Hunter2
bob@corp.local:passw0rd
svc_sql
# lines starting with # are ignored
```

Cracked-hash output such as `domain\user:rid:lm:nt:::password` is **not** parsed
directly — extract the `user:password` (or bare username) columns first, e.g.:

```bash
awk -F: 'NF>=8 && $NF!="" {print $1":"$NF}' secretsdump_cracked.txt > creds.txt
```

Usernames are matched against `samaccountname` first, then the display `name`. A
`[-] not found` means the account in your list is not present in the collected graph
(wrong domain, not collected, or a different name).

## How it works

1. `GET /api/v2/asset-group-tags` → find the built-in **Owned** tag id.
2. For each username, a Cypher lookup resolves the `User` node's ObjectID (SID).
3. `POST /api/v2/asset-group-tags/{id}/selectors` creates an Owned selector
   (seed type `1` = ObjectID) for that SID.
4. `PUT /api/v2/analysis` re-runs analysis; the tool polls
   `GET /api/v2/datapipe/status` until `idle`, then counts `Tag_Owned` nodes.

### BloodHound CE notes

- Owned is a node **kind label** `Tag_Owned` (Tier Zero = `Tag_Tier_Zero`), **not**
  `system_tags`. Query with `MATCH (u:Tag_Owned) RETURN u`.
- `isOwnedObject` / `isTierZero` in node JSON are computed API display fields, **not**
  stored graph properties — `WHERE u.isOwnedObject = true` in Cypher always returns 0.
- The legacy `/api/v2/asset-groups` selectors endpoint no longer drives the
  `Tag_Owned` label in current BH CE; this tool uses the asset-group-tags API.
- The Explore Cypher panel only renders nodes/edges — scalar/aggregate `RETURN`s
  (`count()`, `u.name`) show "No results" even when a value exists. Use the API for scalars.