# Setup guide: model and connectors

This guide gets Compensated Anarchist working end to end:
- a model to run the agents;
- the connectors that give them data and reach (Security Onion, Elastic, Splunk, Velociraptor, MISP, OpenCTI, Archer);
- local forensic tools;
- the scope the rules of engagement enforce.

Only a model is strictly required. Every connector is optional: enable the ones you have. The agents can only
use what is connected.

Each connector section follows the same pattern:
1. **What it gives the team.**
2. **On the other system:** the account or key to create, using the least privilege that works.
3. **On the harness host:** the settings in `config/.env`.
4. **Check:** confirm it connected.

---

## Starting and stopping

```bash
scripts/start.sh            # start (the first run also builds everything and asks for the dashboard account)
scripts/stop.sh             # stop
```

- **The first run** runs `scripts/install.sh` when nothing is installed yet: the Python environment, the config
  files and every folder. Then it asks you to create the **dashboard account**, the username and password
  you sign in with. The password is stored only as a salted scrypt hash in `config/secrets/` (mode 600).
- **Every start** prints a sign-in link with a **new access token**; the previous token stops working. Signing in
  takes the token plus the username and password. If it is already running, start offers to restart it with a
  new token.
- **Your data is never touched.** Start only creates what is missing; it never overwrites, empties or deletes
  anything. Cases, conversations, memory, skills, audit logs, plans and reports stay across stops and starts.
  Stop shuts down cleanly, so the audit log and chat history are closed properly.
- **Every start asks three questions;** press Enter to keep the default shown, which is your last choice:
  - **Posture:** OBSERVE (watch and investigate; response actions are refused) or RESPOND (response actions
    allowed, each still approved by you).
  - **Address:** the main address (this host's network address, over HTTPS with a self-signed certificate that
    start makes, renews before it expires, and whose fingerprint it prints) or this host only (127.0.0.1).
  - **Case:** an existing case, or a new case id.

  An option skips its question (`--posture respond`, `--localhost`, `--case IR-0042`), and `--yes` skips them all.
  Without a terminal (cron, systemd) it uses the saved answers. Other options: `--port`, `--model`,
  `--foreground`.
- **Change them while it runs** on the dashboard's Settings page, under "Posture, address and case":
  - **Posture** applies at once (switching to RESPOND asks you to confirm).
  - **Case** switches in place; connectors reconnect and you stay signed in.
  - **Address** restarts the dashboard in place on the new address, with the same access token; sign in again there.

  Every change is audited and becomes the default the next start offers.
- **Sign-ins end** after 12 hours without activity (`dashboard.session_idle_hours`) and at every restart.
- **Account:** `canarchist account status | passwd | reset` (reset replaces a forgotten account).
- Runtime files (pid, log, the current token) are in `run/` (mode 700, git-ignored).

---

## 0. Before you start

**What the harness host needs:**
- Linux, with Python 3.11 or newer and its `venv` module (Debian/Ubuntu: `apt install python3-venv`).
- `git` and `openssl`. The dashboard makes its own self-signed certificate with openssl when it serves beyond
  localhost.
- `bwrap` (bubblewrap) to onboard new tools: `dnf install bubblewrap` or `apt install bubblewrap`. Without it,
  everything else still works.
- Access to PyPI for the Python packages, or a wheelhouse you copy in (air-gapped; see below).
- No root. Only the optional `--harden-vault` uses sudo.

**Install:** one script takes you from `git clone` to ready-to-configure. It is safe to re-run, and never
overwrites your settings:
```bash
git clone https://github.com/BushidoCyb3r/compensatedanarchist.git
cd compensatedanarchist
./scripts/install.sh               # --help for options; scripts/start.sh runs it for you on the first start
```
What the script does:
1. **Python and packages:** finds Python 3.11 or newer, creates `.venv`, and installs the harness with the
   Claude and Velociraptor client libraries.
   - `--forensics` also installs the Python forensic tools.
   - `--wheelhouse DIR` installs offline, for air-gapped networks. Build the wheelhouse on a connected machine
     with the same OS and Python version, in a checkout:
     `python3 -m pip wheel -w wheelhouse pip setuptools wheel '.[connectors]'` (add `pytest` for `--test`,
     `.[connectors,forensics]` for `--forensics`). Copy `wheelhouse/` across.
   - `--core` installs the harness only, without the Claude and Velociraptor libraries.
2. **Configuration files:**
   - `config/.env` (600), from `config/env.example`;
   - `config/secrets/` (700);
   - your site scope file `config/roe.local.yaml` (600), a copy of `roe.yaml`;
   - `config/models.local.yaml`, for your own model profiles.
3. **Folders:** `evidence/`, the vault `evidence/vault/` (700), `forensics/` (per-case evidence folders),
   `cases/` and `memory/`.
4. **The dashboard account:** in a terminal it asks for the username and password you will sign in with.
   Otherwise the first `scripts/start.sh` asks.
5. **Checks:** confirms all of these are git-ignored, reports:
   - the vault's mount;
   - the system tools the harness uses (`openssl`, `bwrap`);
   - which local forensic tools are present (it installs none of them).
   
   Then it runs `doctor`.
   - `--test` also installs pytest and runs the test suite.
   - `--attack` downloads the MITRE ATT&CK data (section 8b).
   - `--harden-vault` mounts the vault noexec (sudo).

**Updating:** `git pull`, then `./scripts/install.sh` again: it reinstalls the package and leaves your settings,
account and data alone. Stop and start the dashboard afterwards. Your `config/roe.local.yaml` is a copy made at
install time, so it does not get rules that later versions add to `roe.yaml`: `doctor` and every start list any it
is missing. Copy them across in the same place (the first matching rule wins), or write your own rule for each.

**Moving or copying an installation:** `.venv` is tied to its folder. After moving the checkout, delete `.venv`
and run `./scripts/install.sh` again. Your data and settings are plain files and move with it.

**Where secrets live:**
- `config/.env` holds every URL, key and token.
- `config/secrets/` holds credential files (Velociraptor API configs, CA bundles, client certs).
- git ignores both, and so does `config/*.local.yaml`.
- `harness.yaml` and `roe.yaml` only reference secrets as `${VARIABLE}`, so those files can be shared safely.

**Loading the settings:** every `canarchist` command reads `config/.env` itself; there is nothing to `source`.
A variable already set in your shell wins over the file, so you can override one for a single run (e.g.
`CA_MODEL=claude-haiku canarchist run ...`). A running dashboard re-reads `.env` when the model picker or Settings
opens and before each run, so a new or rotated **model** key works without a restart. **Connector** credentials
(Security Onion, Elastic, Splunk, Velociraptor, ...) are read when the connectors start: restart the dashboard
after changing those. `CA_ENV_FILE=/path/to/file` points the harness at a different file.

**Check what is connected at any time:**
```bash
.venv/bin/canarchist doctor --case SETUP-CHECK
```
`doctor` prints every connector (`connected (N tools)` or the error), each model profile, and every tool
with its ROE tier (auto / notify / approve / deny).

**Network:** every connector is an outbound connection *from the harness host* to the other system. Open
each port to the harness host's IP only, never to the whole network.

**Credentials ever pasted into a chat, ticket or email:** rotate them once setup works.

---

## 1. Model (required)

The agents need one model profile. Profiles live in **`config/models.yaml`**: every enabled profile there is a
choice in the dashboard's model picker (and for `--model <profile>` / `/model` on the CLI). The file ships with
profiles for GenAI, Claude, ChatGPT and common local servers, plus a **`my-local-model` template**: fill in its
`CHANGE-ME` values (server URL, model id, context size) and it becomes a choice. Copy the block for each extra
model. The top of the file documents every field.

- **Site profiles** go in `config/models.local.yaml` (git-ignored, same layout). It is merged over
  `models.yaml`: add your own profiles, override a field of a shipped one, set `default_model`, or hide one with
  `enabled: false`.
- **Secrets never go in either file.** Write `${VARIABLE}` there and put the value in `config/.env`.
- **The default** is `default_model:`. The shipped one is the `my-local-model` template, so until you fill it in or
  choose another profile, a run stops at once and says which model to set up. Set yours with `default_model:` in
  `models.local.yaml` (or `CA_MODEL` in `.env`); `--model` or the picker overrides it for a run. The harness never
  falls back to another model by itself, so nothing is sent to a hosted model you did not choose.
- **Edits apply without a restart:** the dashboard re-reads the files, and `config/.env`, when the picker or
  Settings opens and before each run. A new API key for a model works straight away. A
  profile that is missing its API key or still has `CHANGE-ME` values shows as "needs setup", with the reason,
  and cannot be picked. `canarchist doctor` lists the same.

| You have | Profile | Set in `.env` |
|---|---|---|
| vLLM, Ollama, llama.cpp, LM Studio, TGI, LiteLLM, an MLX server, or any OpenAI-compatible endpoint | `local-ollama`, `local-vllm`, `local-textmode`, or fill in `my-local-model` | the URL and model id (or edit them in the template); an API key only if the server needs one |
| A government or enterprise AI gateway (GenAI.mil or your organization's, OpenAI-compatible) | `genai-gateway` | `GENAI_BASE_URL`, `GENAI_MODEL`, `GENAI_API_KEY`; `GENAI_API_KEY_HEADER` if it is not `Authorization: Bearer`; `DOD_CA_BUNDLE`; `GENAI_CLIENT_CERT` / `GENAI_CLIENT_KEY` for mTLS. Get the API root and model ids from the gateway's documentation or help desk. |
| Claude (Anthropic API) | `claude-opus`, `claude-sonnet`, `claude-haiku` | `ANTHROPIC_API_KEY`. Everything the agents read goes to Anthropic: check your data rules first. |
| ChatGPT (OpenAI API) | `chatgpt` (GPT-5.6 Sol), `chatgpt-luna` (GPT-5.6 Luna) | `OPENAI_API_KEY`; `OPENAI_MODEL` / `OPENAI_MODEL_SMALL` to use other ids. Everything the agents read goes to OpenAI: check your data rules first. |

**Steps:**
1. **Find the exact model id the server expects.** For OpenAI-compatible servers, `GET <base_url>/models`
   lists them.
2. **Check tool calling.** The harness depends on native function calling. For vLLM start the server with
   `--enable-auto-tool-choice --tool-call-parser <parser for your model>`. If the server cannot do tool
   calls, set `tool_mode: text` in the profile (as `local-textmode` does).
3. **Set `context_tokens`** at or below the server's real limit, minus `max_output_tokens`. History is
   compacted at 75% of it.
4. **Streaming** is on by default (`stream: true`). If a gateway rejects or ignores it, the harness falls back
   on its own. Set `stream: false` to never ask.
5. **Test with a tiny read-only run:**
   ```bash
   .venv/bin/canarchist run --case SETUP-CHECK --model <profile> --posture observe --non-interactive "Reply with OK."
   ```

**Model size matters.** Small models (about 4B) can call tools, but they generalize from samples, skip
false-positive checks and fall into repetition loops. The harness guards against the worst of this: sample
warnings, empty-reply nudges and a loop guard. Still, use the largest model you can for the lead and the
triage/hunting experts. `experts.overrides` in `harness.yaml` can give each expert its own model.

---

## 2. Security Onion 3

**What it gives the team:**
- Suricata and SO Detections (Sigma/YARA) alerts, summarized by rule with source → destination pairs.
- Zeek searches, ES|QL, community_id pivots, beacon candidates, IOC sweeps, field stacking.
- `pair_counts`: who talked to whom over the whole time window.

It is read-only, and works through the grid's Elasticsearch on the manager.

**On the Security Onion manager:**
1. **Open port 9200 to the harness host** the Security Onion way, not with raw iptables. In
   *Administration → Configuration → firewall*, add a port group for TCP 9200 and a host group containing
   the harness host's IP, and assign them to the manager.
2. **Create a read-only API key.** In Kibana *Dev Tools*:
   ```
   POST /_security/api_key
   {
     "name": "canarchist-readonly",
     "role_descriptors": {
       "canarchist_read": { "indices": [ { "names": ["logs-*"], "privileges": ["read"] } ] }
     }
   }
   ```
   Copy the `encoded` value from the response; that is the key. A SOC account (`SO_USER` / `SO_PASS`) also
   works, but a key you can scope and revoke is better.
3. **Copy the grid CA** (`/etc/pki/ca.crt` on the manager) to `config/secrets/so-ca.crt`.

**On the harness host (`config/.env`):**
```
SO_ENABLED=true
SO_URL=https://<manager>:9200
SO_API_KEY=<encoded key>
SO_VERIFY=/path/to/config/secrets/so-ca.crt      # or false while testing (not for production)
```
The defaults for `SO_INDEX` (`logs-*-so`), `SO_ALERT_INDEX` (`logs-*.alerts-so`) and `SO_ZEEK_INDEX`
(`logs-zeek-so`) match Security Onion 3.4. `SO_ALERT_QUERY` adds a filter to every alert query, for example
to drop a noisy rule.

**Check:**
- `doctor` shows `mcp security_onion connected (11 tools)`.
- **Optional live test:**
  `CA_LIVE_ES_URL=... CA_LIVE_ES_API_KEY=... CA_LIVE_ES_VERIFY=... CA_LIVE_SO=1 .venv/bin/python -m pytest tests/test_siem_live.py`

**Notes:**
- **Use this connector for a Security Onion grid**, even if you also enable the Elastic one. The Elastic
  connector's alert tools read Elastic Security's detection index, which is empty on Security Onion.
- A key without `view_index_metadata` is fine: data stream listing falls back to a read-only aggregation.
- **Security Onion Pro** also ships an official MCP server (Connect API, OQL). It can be added alongside; see
  the comment block under `security_onion` in `harness.yaml`.

---

## 3. Elastic (Elasticsearch / Elastic Security)

**What it gives the team:** Lucene, DSL, ES|QL and EQL search; index listing; field stacking; IOC sweeps;
`pair_counts`; and Elastic Security detection alerts. It is read-only.

**On the Elastic cluster:**
1. **Open 9200** (or your Elasticsearch port) to the harness host.
2. **Create a read-only API key** as in section 2, with the index patterns you want searchable. To include
   Elastic Security alerts, add `.alerts-security.alerts-*`:
   ```
   "indices": [ { "names": ["logs-*", ".alerts-security.alerts-*"], "privileges": ["read"] } ]
   ```

**On the harness host:**
```
ES_ENABLED=true
ES_URL=https://<elasticsearch>:9200
ES_API_KEY=<encoded key>
ES_VERIFY=/path/to/ca.pem          # true for public CAs, false only while testing
ES_DEFAULT_INDEX=logs-*
```

**Check:** `doctor` shows `mcp elastic connected (10 tools)`. The optional live test is the same command
as section 2, without `CA_LIVE_SO=1`.

---

## 4. Splunk (Enterprise / Enterprise Security)

**What it gives the team:** SPL search, index and data inventory, field summaries, IOC sweeps, and ES
notable events. It is read-only by construction: SPL that writes or runs anything (`delete`, `collect`,
`outputlookup`, `sendemail`, `script`, `run`, `map`, and so on) is refused before it reaches Splunk.

**On Splunk:**
1. **Enable token authentication:** *Settings → Tokens → Token Settings → Enable*.
2. **Create a user** whose role can search only the indexes the team needs (no admin, no write
   capabilities), then create a token for it (*Settings → Tokens → New Token*).
3. **Open the management port** (8089) to the harness host.

**On the harness host:**
```
SPLUNK_ENABLED=true
SPLUNK_URL=https://<splunk>:8089
SPLUNK_TOKEN=<token>
SPLUNK_VERIFY=/path/to/ca.pem
```

**Check:** `doctor` shows `mcp splunk connected`.

> Splunk is the least-tested connector: it has never run against a real Splunk. Validate search and
> notable-event results on your instance before relying on them.

---

## 5. Velociraptor

**What it gives the team:** endpoint visibility and response. It is split across two keys for least
privilege:

| Connector | API role | Tools |
|---|---|---|
| `velociraptor` | `investigator,api` | 15: clients, client info, flow history, artifact search/info, collect, flow status/results/uploads, labels, cancel, hunts, memory acquisition (Windows) |
| `velociraptor_admin` (optional) | `administrator,api` | 4: evidence download (SHA-256 and size checked), quarantine, unquarantine, server VQL |

Only the incident responder gets every admin tool. The forensicator and endpoint analyst get download only.

**On the Velociraptor server, the scripted way:** copy `scripts/velociraptor_setup.sh` to the server and run
it as root:
```bash
sudo ./velociraptor_setup.sh --harness-ip <harness host IP>            # investigator key only
sudo ./velociraptor_setup.sh --harness-ip <harness host IP> --admin    # plus the admin key
```
What it does:
- **Finds the installation** (service, binary, config, service user) from systemd.
- **Creates the key(s)** as the service user and backs up `server.config.yaml` first.
- **Exposes the API** by moving its listen address to the IP that can reach the harness (`--bind` to choose
  another), and allows the port from the harness host only:
  - **firewalld:** a rich rule in the zone of the interface that reaches the harness. It warns if the port is
    already open to everyone, which would make that rule pointless.
  - **ufw:** an allow rule for the harness address.
  - **Anything else** (nftables or iptables directly, or a network firewall): it tells you which rule to add.

  If other programs on the server use the API through `127.0.0.1`, pass `--bind 0.0.0.0` so they keep working.
  The firewall rule still limits who can connect.
- **Restarts the server and verifies** each key with a read-only query.
- **Prints a report with no secrets:** version, API address, client count and ranges, the harness
  workstation's own client id, stale clients, and a ready-to-paste `allowed_targets` / `protected_assets` block
  for `roe.local.yaml`.

It asks before every change, has `--dry-run`, and never prints key contents. Run `--dry-run` first to see the
plan. `--deliver user@harness:<repo>/config/secrets/` copies the keys with scp and offers to shred the
server-side copies. It finds a standard package install (the `velociraptor_server` service) on its own. For
anything else, pass `--binary`, `--config` and `--user`, and restart the server yourself. The API must listen
on TCP (`API: bind_scheme: tcp`, the default). `--help` lists every option.

**On the Velociraptor server, by hand** (run the commands as the service user, usually `velociraptor`, so the
datastore files it writes stay owned correctly):
1. **Create the investigator API client:**
   ```bash
   sudo -u velociraptor velociraptor --config /etc/velociraptor/server.config.yaml config api_client \
       --name canarchist --role investigator,api canarchist.api.yaml
   ```
2. **Optional: the admin client.** It is powerful: server VQL can run commands on the server. Create it
   only if you want evidence download and quarantine:
   ```bash
   sudo -u velociraptor velociraptor --config /etc/velociraptor/server.config.yaml config api_client \
       --name canarchist_admin --role administrator,api canarchist_admin.api.yaml
   ```
3. **Expose the API.** In `server.config.yaml`, under `API:`, change `bind_address` from `127.0.0.1` to the
   server's IP (or `0.0.0.0`). Back up the file first.
4. **Firewall:** allow TCP 8001 to the server **from the harness host only**. Use the host firewall, or your
   hypervisor or network firewall if the host has none. The API requires mutual TLS, but don't rely on that
   alone.
5. **Restart the server** (`systemctl restart velociraptor_server`). A running server doesn't see new API
   users until it restarts; otherwise the connector reports `User not found`.
6. **Point each file at the reachable address:** set `api_connection_string: <server-ip>:8001`. Leave the
   TLS fields alone.
7. **Verify each file:**
   `velociraptor --api_config canarchist.api.yaml query "SELECT client_id FROM clients() LIMIT 1"`.
   The investigator role may return nothing for `SELECT * FROM info()`. That is a permission difference, not
   a failure, and the connector doesn't use `info()`.
8. **Copy the files to the harness host** with `scp`, never by pasting: they contain a private key. Then
   delete the server-side copies (`shred -u`). The server can always issue new ones.

**On the harness host:**
```bash
chmod 600 config/secrets/*.api.yaml
```
```
VELO_ENABLED=true
VELO_API_CONFIG=/full/path/config/secrets/canarchist.api.yaml
VELO_ADMIN_ENABLED=true             # only if you made the admin key
VELO_ADMIN_API_CONFIG=/full/path/config/secrets/canarchist_admin.api.yaml
VELO_ORG_ID=                        # multi-org servers only
VELO_DOWNLOAD_DIR=                  # empty = <first evidence root>/velociraptor (inside the forensic jail)
```
Then **set the scope (section 9) before the first run.** With an empty scope, any enrolled client can be
targeted.

**Check:**
- `doctor` shows `mcp velociraptor connected (15 tools)`, and `velociraptor_admin connected (4 tools)` if you
  made the admin key.
- **Optional live test:**
  `CA_VELO_API_CONFIG=... CA_VELO_ADMIN_API_CONFIG=... .venv/bin/python -m pytest tests/test_velociraptor_live.py`

**Human in the loop (built in):**
- **Nothing touches an endpoint without an analyst saying yes.** That covers every collection (triage
  included), hunts, memory acquisition, evidence downloads, labels, quarantine, unquarantine and server VQL.
- **It's enforced in code** (`roe.HUMAN_GATED`). A `roe.yaml` rule can make these stricter (`deny`), never
  `auto` or `notify`.
- **Read-only lookups need no approval:** listing clients, flows, artifacts and hunt results, and reading
  results already on the server.
- **Remote-shell artifacts are denied.**
- **Posture:** in OBSERVE, investigation actions (collections, downloads, labels, hunts, memory) can still be
  *requested* and approved. Response actions (quarantine, unquarantine, server VQL) are denied outright and
  need RESPOND posture plus approval.
- **Where you approve:** the dashboard's two-step approval dialog, or the terminal prompt in `canarchist chat`.
  Non-interactive runs (`run --non-interactive`) deny every approval.

**Evidence vault (files pulled from endpoints):**
- **Where files land:** every file downloaded from Velociraptor goes to `evidence/vault/velociraptor/<client>/<flow>/`.
  The harness forces this location: a `VELO_DOWNLOAD_DIR` outside the vault is ignored.
- **Permissions:** files are read-only and never executable (0400). Each flow's folder is locked (0500) when
  its download finishes.
- **Defanging:** executables and scripts, detected by content (PE, ELF, Mach-O, `#!`) and by risky
  extensions, get a `.quarantined` suffix so no file association can launch them. `MANIFEST.jsonl` records
  each file's endpoint path, stored name and SHA-256.
- **Nothing runs from evidence:** the analysis tools read files and never run them, and `local_run` refuses to
  execute anything inside the evidence roots or the case folder.
- **Root-only hardening (recommended):** mount the vault `noexec,nosuid,nodev`, so nothing in it can be
  executed even on purpose, through an interpreter or a loader. `doctor` shows whether it is:
  ```bash
  V=/path/to/compensatedanarchist/evidence/vault
  sudo mount --bind "$V" "$V" && sudo mount -o remount,bind,noexec,nosuid,nodev "$V"
  # keep it across reboots:
  echo "$V $V none bind,noexec,nosuid,nodev 0 0" | sudo tee -a /etc/fstab
  ```
  To freeze a specific piece of evidence completely, run `sudo chattr -R +i <flow folder>`. Not even the
  owner can then change or delete it; `chattr -R -i` undoes this.

**Notes:**
- **The harness host is a client too.** If the harness workstation runs a Velociraptor client, put its client
  id under `protected_assets`, and do the same for the Velociraptor server.
- **Artifact names:** `Windows.KapeFiles.Targets` is no longer built in as of 0.77; import it with
  `Server.Import.Extras`.

---

## 6. MISP

**What it gives the team:** IOC and event search, warninglist checks (known-benign values) and event detail.
Two narrow writes: add a sighting, and create an event. Events are always created **unpublished**, visible
to your organisation only, so an analyst publishes them.

**On MISP:**
1. **Create a user** for the harness in your organisation, with a role that allows sightings and event
   creation (e.g. *User*). If you only want lookups, use a read-only role; the two write tools will then
   fail cleanly.
2. **Create an auth key** for it (*My profile → Auth keys → Add*). Restrict it to the harness host's IP
   under *Allowed IPs*.

**On the harness host:**
```
MISP_ENABLED=true
MISP_URL=https://<misp>
MISP_KEY=<auth key>
MISP_VERIFY=/path/to/ca.pem
```

**Check:** `doctor` shows `mcp misp connected`.

---

## 7. OpenCTI

**What it gives the team:** IOC lookup with context (related threat actors, malware, campaigns), entity
search, relationships, and read-only GraphQL. It is read-only.

**On OpenCTI:**
1. **Create a user** in a group whose role has knowledge *access* only (no create, update or delete).
2. **Copy that user's API token** from its profile.

**On the harness host:**
```
OPENCTI_ENABLED=true
OPENCTI_URL=https://<opencti>
OPENCTI_TOKEN=<token>
OPENCTI_VERIFY=/path/to/ca.pem
```

**Check:** `doctor` shows `mcp opencti connected`.

---

## 7b. Archer

**What it gives the team:** Archer's findings from Zeek (beaconing, exfiltration, lateral movement, DNS tunneling,
threat-intel matches), per-host roll-ups, campaigns, the raw Zeek records behind a finding and its 30-day history.
Read-only: the connector never acknowledges, escalates, annotates or re-runs anything. The network analyst, threat
hunter and alert triage experts use it, and verify each finding in the Zeek data before it counts.

**On Archer:**
1. **Create a Viewer account** for the harness. The display name can be anything (e.g. *Compensated Anarchist*); the
   login uses the account's **email**. The connector refuses to work with any role other than viewer.
2. **Note Archer's certificate fingerprint** (SHA-256). On the Archer host,
   `openssl x509 -in /data/tls/server.crt -noout -fingerprint -sha256` prints it; an Archer admin also sees it at
   `GET /api/sensors/info` (admin-only, so the connector's Viewer account cannot read it).

**On the harness host** (`config/.env`; the password goes nowhere else):
```
ARCHER_ENABLED=true
ARCHER_URL=https://<archer>:8443
ARCHER_EMAIL=<the Viewer account's email>
ARCHER_PASSWORD=<its password>
ARCHER_TLS_FINGERPRINT=<SHA-256, colons allowed>
```
Without a fingerprint, the first call fails and its message gives the fingerprint Archer presented: compare it
with Archer's before you pin it. `ARCHER_VERIFY=false` turns certificate checking off (not recommended).

**Check:** `doctor` shows `mcp archer connected` and the `archer__*` tools as `auto`. Then run the acceptance
checks against your Archer: `CA_LIVE_ARCHER=1 .venv/bin/python -m pytest -q tests/test_archer_live.py`.

---

## 8. Case evidence folders and local forensic tools (on the harness host)

**Where to put evidence for a case:** every case gets its own folder, `forensics/<case-id>/`. The harness
creates it the first time the case is used, with subfolders `disk/ memory/ logs/ network/ mobile/ triage/
other/`. Drop disk images, memory dumps, EVTX, PCAPs, triage packages, mobile extractions or malware samples
there, in any subfolder.
- **Types are detected by content,** so a misplaced or renamed file is still recognized.
- **Agents start here:** every agent is told where the folder is, and the forensics playbook starts from it.
  Its first tool, `local_case_evidence`, lists the folder and the evidence vault with each item's detected type
  and chain-of-custody status.
- **Shown in the dashboard and `doctor`:** the dashboard's case panel shows the folder under *Evidence*, with a
  button to start the forensics playbook. `doctor` prints it too.
- **Read, never run:** the folder is an evidence root, so the analysis tools can read it, and nothing in it is
  ever executed (`local_run` refuses).
- **Hashed before analysis:** the team hashes and registers each item before analyzing it. Don't edit evidence
  after dropping it.
- **Location:** `harness.forensics_dir` in `harness.yaml` (default `../forensics`, git-ignored). For the same
  no-execute protection as the vault, mount it `noexec,nosuid,nodev` (section 5).

### Local forensic tools

These tools run locally against files under the evidence roots (`evidence/`, `forensics/`). The evidence is
read-only, and outputs go to the case directory.

**Install what you need**, and **ask your security team before downloading tools onto an operator
workstation**, which is usually monitored. Then point the harness at anything that isn't on `PATH`:
```
YARA_RULES=/opt/rules/yara
SIGMA_RULES=/opt/rules/sigma
CAPA_RULES=/opt/rules/capa-rules
EZ_TOOLS_DIR=/opt/zimmermantools        # needs `dotnet` on Linux
MEMPROCFS_PYTHON=                       # python with `pip install memprocfs`
ALEAPP_PATH=/opt/ALEAPP/aleapp.py
ILEAPP_PATH=/opt/iLEAPP/ileapp.py
LEAPP_PYTHON=
```
Other binaries (`vol`, `log2timeline.py`, `tshark`, `zeek`, `capa`, `floss`, `exiftool`, etc.) are found on
`PATH`; rename them under `forensics.binaries` in `harness.yaml` if needed. `local_run` may only execute the
binaries in `forensics.allowed_binaries`, with no shell.

**Check:** ask the team to run `local_tools_inventory` (`canarchist chat`, then "which local tools are
installed?"). `doctor` lists the tools and their tiers.

---

## 8b. Hunt planning with MITRE ATT&CK

Planning and hunting are separate jobs:
- **hunt_planner** designs a hunt plan for the actors or techniques you name. It never runs hunt queries and
  holds no search, collection or response tools.
- **threat_hunter** executes hunts. It runs a plan only when you ask for that plan.

**How a hunt plan is made** (the **hunt_plan** playbook):
1. **The lead checks with you first**, before anything is planned or any system is looked at. It asks how to
   build the plan:
   - from your input only;
   - by surveying the connected systems (platforms, which data sources and fields exist);
   - or both, which is the default.
   It also asks about actors or T-codes, platforms, which tools to write queries for, how many hunts, the hunt
   window, and whether to include the actors' software and campaigns. Reply "default" to accept the defaults.
2. **hunt_planner builds it your way.** It pulls each actor's ATT&CK techniques (T-codes), including those from
   their software and attributed campaigns, and maps them to the data that would show them. If you chose a
   survey, it checks what the connected tools can actually see. It then:
   - prioritizes the hunts;
   - writes queries per tool (Security Onion Lucene/ES|QL, Elastic EQL/ES|QL, Splunk SPL, Velociraptor
     artifacts);
   - lists telemetry gaps.
3. **The plan and an ATT&CK Navigator layer** are saved to the case's **hunt plans folder**,
   `cases/<case-id>/hunt_plans/`. Earlier versions are kept in `older/`.
4. **Hunting happens only when you say so.** Ask the lead to hunt from a plan by name. The threat_hunter finds it
   in the hunt plans folder (`hunt_plan_list` / `hunt_plan_read`), runs it over the window you approve, and saves
   `hunt_results_<actors>.md` next to it. The threat_hunter can always read the folder, but reading a plan never
   starts a hunt.

**The ATT&CK data:** the official MITRE ATT&CK STIX bundle (`enterprise-attack.json`, about 45 MB) is kept locally,
so it works air-gapped:
```bash
.venv/bin/canarchist attack fetch                 # downloads it from MITRE's attack-stix-data GitHub repository
.venv/bin/canarchist attack fetch --from /media/usb/enterprise-attack.json   # air-gapped: import a copied file
.venv/bin/canarchist attack status                # version and counts
.venv/bin/canarchist attack group "APT29"         # quick look at an actor (names, aliases and G-ids all work)
```
- **Location:** `data/attack/` (git-ignored), set by `attack.stix` in `harness.yaml`. `ATTACK_STIX` overrides
  it, comma-separated, e.g. to add the ICS or mobile bundles (`--domain ics|mobile`).
- **Updating:** re-run `fetch` when MITRE releases a new version; no restart is needed.

**To use it:** in the dashboard, pick the **Hunt plan** playbook and name the actors, e.g. "APT29 and Volt Typhoon,
Windows and Linux, last 30 days". From the CLI:
```bash
.venv/bin/canarchist run --case HUNT-0001 --playbook hunt_plan "APT29 and Volt Typhoon"
```

## 8c. Vulnerability assessment (optional; best on a Kali VM)

The `vulnerability_assessment` playbook tasks the `vuln_assessor`. It uses the connectors plus the command-line
assessment tools on the harness host, and writes a vulnerability report with the most likely attack chains.

- **Every action needs your approval:** reads, notes and tasking included, for every agent in that conversation.
  This is built in and cannot be turned off; start a new conversation for other work.
- **Scope is required.** Set `scope.allowed_targets` in your ROE file (section 9) first: with no scope, the
  scanner refuses to run. Put fragile or critical hosts in `protected_assets`.
- **Tools:** on Kali they are already installed. Elsewhere, install the ones you want (nmap at least); the
  assessor only offers what it finds (`vuln_environment`). Without root, nmap is limited to connect scans
  (`-sT -sV`).
- **OBSERVE posture:** scans may still be requested and approved one by one (`observe: ask` on the `vuln_*`
  rule in the ROE file). Set `observe: deny` there to forbid scanning in OBSERVE.
- **Outputs:** `cases/<case>/vuln_assessment/`: the report (`vuln_report_<name>.md`) and `raw/` with every
  command's full output. The dashboard's case panel lists the reports under "Plans & reports".
- **Settings:** `vuln_assessment:` in `harness.yaml`: the allowlist, extra refused options per tool, read-only
  data folders, timeouts.

---

## 9. Scope (rules of engagement)

Connectors give the team reach. The scope decides where response actions may land. Keep your site's scope
in a local copy so your addresses never enter git:

```bash
cp config/roe.yaml config/roe.local.yaml && chmod 600 config/roe.local.yaml
echo 'CA_ROE=roe.local.yaml' >> config/.env
```

Edit `scope:` in `config/roe.local.yaml`:
```yaml
scope:
  enforce: true
  allowed_targets:            # where active actions may land (CIDRs, hostname globs, Velociraptor client ids)
    - 10.20.0.0/16
    - "*.corp.example.mil"
  protected_assets:           # always need approval, even for low-impact actions
    - "C.xxxxxxxxxxxxxxxx"    # the harness workstation's own Velociraptor client
    - 10.20.0.10              # domain controller, Velociraptor server, safety systems...
```

**How the scope is applied:**
- **After an update,** `doctor` and start list any rules `roe.yaml` ships that your file lacks (section 0, *Updating*).
- **Empty `allowed_targets` means no restriction.** Fill it in before enabling Velociraptor or any other
  response-capable connector.
- **Velociraptor client ids are resolved live** to hostname, FQDN and last IP, so CIDR and hostname entries
  apply to them. An id that can't be resolved is denied (fail closed).
- **Posture:** set by `posture:` in your ROE file (the shipped value is `respond`), or per run with
  `--posture observe|respond`. In OBSERVE, response actions (quarantine, server VQL) are denied outright, while
  investigation actions marked `observe: ask` (endpoint collection, evidence download) can still be requested
  and approved. In RESPOND, every approve-tier action asks the analyst. Either way, nothing approve-tier runs
  without a human yes. If your team should default to observing, set `posture: observe` in roe.local.yaml.

---

## 10. Learning, budgets and new tools (`config/harness.yaml`)

The shipped defaults suit most sites. Change them in `harness.yaml`:

- **Budgets** (`budgets:`). Each operation's limits over all its agents together:
  - `max_tokens` (4,000,000), with prompt-cache reads counted at `cached_weight` (0.1);
  - `max_tool_calls` (500);
  - `max_minutes` (90).

  The feed warns at 80 %; at a limit the run stops cleanly and you can carry on with a new message. On a hosted
  model, tokens are money: lower `max_tokens` to cap what one operation can cost.
- **Learning** (`learning:`). `auto_retro: true` runs the after-action review when a playbook mission completes;
  `every_n_missions: N` also runs it after every N other missions. The review uses model time, so on a slow local
  model set `auto_retro: false` and run `/retro` (or *After-action review*) yourself. What it proposes waits on
  the dashboard's **Learning** page for your approval.
- **New tools** (`tool_onboarding:`). Put tools you want the team to use under one of `tool_roots`
  (`/opt`, `/usr/local`, `~/tools`): the tool_integrator looks nowhere else. Every onboarded tool runs in the
  bubblewrap sandbox (`sandbox: bwrap`), so `bwrap` must be installed and work for your user. The installer checks
  this. Adapters, proposals and trial runs are kept in `tool_specs/` (git-ignored). Review proposals on the
  Learning page or with `canarchist tools review`.
- **A new MCP server:** add it under `mcp_servers:` with `quarantine: true` (there is an example at the end of
  that section). Its tools stay unusable until you approve them.
- **Checking a model before you rely on it:** `.venv/bin/canarchist redteam --model <profile>` runs the
  prompt-injection checks: six scenarios, stub tools only, reports in `cases/_redteam/`. It calls the model, so
  on a hosted model it costs tokens.

---

## 11. Final check

```bash
.venv/bin/canarchist doctor --case SETUP-CHECK
.venv/bin/canarchist run --case SETUP-CHECK --posture observe --non-interactive \
    "Smoke test: summarize the alerts from the last 24 hours, the top rules and the source -> destination pairs. Read-only."
scripts/start.sh --case IR-0001     # prints the sign-in link and this start's access token; scripts/stop.sh stops it
```

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| A connector shows an error in `doctor` | a value missing from `config/.env` (or a stale one exported in this shell, which wins over the file), wrong URL or port, or the firewall |
| TLS / certificate errors | `*_VERIFY` should point at the CA that signed the server certificate |
| `401` / `403` | Wrong key, an expired token, or the key lacks `read` on the index pattern |
| Velociraptor `User not found` | The server was not restarted after `config api_client` |
| Velociraptor connection refused | `API: bind_address` is still `127.0.0.1`, or port 8001 is blocked |
| "0 alerts" from a Security Onion grid | Only the Elastic connector is enabled; enable the Security Onion connector |
| Agent replies loop or come back empty | The model is too small for the task; try a larger one (the loop guard cuts loops off) |
| Approval-tier actions always denied | Response actions need RESPOND posture (by design), the target is outside `allowed_targets`, or the run is non-interactive |
| `doctor` says the vault is not on a noexec mount | Run the bind-mount commands in section 5 (root); files are still read-only and non-executable meanwhile |
| `install.sh`: "Python 3.11 or newer is required" or "lacks venv/ensurepip" | Install a newer Python (and `python3-venv` on Debian/Ubuntu), or pass `--python /path/to/python3.x` |
| `start.sh`: "No dashboard account yet" | It was run without a terminal. Run `scripts/start.sh` in a terminal once, or `.venv/bin/canarchist account create` |
| `start.sh`: "openssl is needed" | Install openssl, or serve on this host only with `scripts/start.sh --localhost` |
| `start.sh`: "Port 8765 ... is in use" | Another program (or another installation's dashboard) has the port: `--port 8766` |
| The dashboard link does not open from another machine | It is bound to 127.0.0.1. Choose the main address at start (or on the Settings page) and open the port to your workstation |
| Tool onboarding fails with a sandbox error | `bwrap` is missing, or user namespaces are disabled (`sysctl user.max_user_namespaces`; Ubuntu 24.04+ also restricts them with AppArmor) |
| "Stopped: this run reached its budget" | The operation hit a `budgets:` limit (section 10). Send a new message to carry on, or raise the limit |
| "No MITRE ATT&CK data" (hunt or emulation plans) | `.venv/bin/canarchist attack fetch`, or `--from <file>` with a copied `enterprise-attack.json` (section 8b) |
| `velociraptor_setup.sh`: "no Velociraptor server service found" | Not a standard package install: pass `--binary`, `--config` and `--user` |
