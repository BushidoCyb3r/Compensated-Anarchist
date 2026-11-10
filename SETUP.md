# Setup guide: model and connectors

This guide gets Compensated Anarchist working end to end:
- a model to run the agents;
- the connectors that give them data and reach (Security Onion, Elastic, Splunk, Velociraptor, MISP, OpenCTI);
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

## 0. Before you start

**Install:** one script takes you from `git clone` to ready-to-configure. It is safe to re-run, and never
overwrites your settings:
```bash
git clone <repo> compensatedanarchist && cd compensatedanarchist
./scripts/install.sh               # --help for options
```
What the script does:
1. **Python and packages:** finds Python 3.11 or newer, creates `.venv`, and installs the harness with the
   Claude and Velociraptor client libraries.
   - `--forensics` also installs the Python forensic tools.
   - `--wheelhouse DIR` installs offline, for air-gapped networks.
2. **Configuration files:** creates `config/.env` (600) from the template, `config/secrets/` (700), and your
   site scope file `config/roe.local.yaml` (600).
3. **Folders:** creates `evidence/`, the vault `evidence/vault/` (700), `cases/` and `memory/`.
4. **Checks:** confirms all of these are git-ignored, reports the vault's mount and which local forensic tools
   are present (it installs none of them), then runs `doctor`.
   - `--test` also runs the test suite.
   - `--harden-vault` mounts the vault noexec (sudo).

**Where secrets live:**
- `config/.env` holds every URL, key and token.
- `config/secrets/` holds credential files (Velociraptor API configs, CA bundles, client certs).
- git ignores both, and so does `config/*.local.yaml`.
- `harness.yaml` and `roe.yaml` only reference secrets as `${VARIABLE}`, so those files can be shared safely.

**Load the settings** before every `canarchist` command, in each new shell:
```bash
set -a; source config/.env; set +a
```

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

The agents need one model profile. Profiles live under `models:` in `config/harness.yaml`. Pick the default
with `CA_MODEL` in `.env`, or per run with `--model <profile>`.

| You have | Profile | Set in `.env` |
|---|---|---|
| vLLM, Ollama, llama.cpp, LM Studio, TGI, LiteLLM, an MLX server, or any OpenAI-compatible endpoint | `local-vllm`, `local-ollama`, `lab-mlx`, or copy one | the URL, model id, and API key if the server needs one |
| A government or enterprise AI gateway (OpenAI-compatible) | `genai-gateway` | `GENAI_BASE_URL`, `GENAI_MODEL`, `GENAI_API_KEY`; `GENAI_API_KEY_HEADER` if it is not `Authorization: Bearer`; `DOD_CA_BUNDLE`; `GENAI_CLIENT_CERT` / `GENAI_CLIENT_KEY` for mTLS |
| Claude (Anthropic API) | `claude-opus`, `claude-sonnet`, `claude-haiku` | `ANTHROPIC_API_KEY`. Everything the agents read goes to Anthropic: check your data rules first. |

**Steps:**
1. **Find the exact model id the server expects.** For OpenAI-compatible servers, `GET <base_url>/models`
   lists them.
2. **Check tool calling.** The harness depends on native function calling. For vLLM start the server with
   `--enable-auto-tool-choice --tool-call-parser <parser for your model>`. If the server cannot do tool
   calls, copy the `local-textmode` profile (`tool_mode: text`).
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
- **Exposes the API** by moving its listen address to the IP that can reach the harness, and allows the port
  from the harness host only (firewalld or ufw; otherwise it tells you which network rule to add).
- **Restarts the server and verifies** each key with a read-only query.
- **Prints a report with no secrets:** version, API address, client count and ranges, the harness
  workstation's own client id, stale clients, and a ready-to-paste `allowed_targets` / `protected_assets` block
  for `roe.local.yaml`.

It asks before every change, has `--dry-run`, and never prints key contents. `--deliver user@harness:<repo>/config/secrets/`
copies the keys with scp and offers to shred the server-side copies.

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

## 10. Final check

```bash
set -a; source config/.env; set +a
.venv/bin/canarchist doctor --case SETUP-CHECK
.venv/bin/canarchist run --case SETUP-CHECK --posture observe --non-interactive \
    "Smoke test: summarize the alerts from the last 24 hours, the top rules and the source -> destination pairs. Read-only."
.venv/bin/canarchist dashboard --case IR-0001     # add --host <ip> --tls-cert <pem> --tls-key <pem> to serve beyond localhost
```

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| A connector shows an error in `doctor` | `.env` not loaded in this shell (`set -a; source config/.env; set +a`), wrong URL or port, or the firewall |
| TLS / certificate errors | `*_VERIFY` should point at the CA that signed the server certificate |
| `401` / `403` | Wrong key, an expired token, or the key lacks `read` on the index pattern |
| Velociraptor `User not found` | The server was not restarted after `config api_client` |
| Velociraptor connection refused | `API: bind_address` is still `127.0.0.1`, or port 8001 is blocked |
| "0 alerts" from a Security Onion grid | Only the Elastic connector is enabled; enable the Security Onion connector |
| Agent replies loop or come back empty | The model is too small for the task; try a larger one (the loop guard cuts loops off) |
| Approval-tier actions always denied | Response actions need RESPOND posture (by design), the target is outside `allowed_targets`, or the run is non-interactive |
| `doctor` says the vault is not on a noexec mount | Run the bind-mount commands in section 5 (root); files are still read-only and non-executable meanwhile |
