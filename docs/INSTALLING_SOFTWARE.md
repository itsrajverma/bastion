# Installing software with Bastion

Bastion can install a fixed catalog of server software — nginx, Apache, PHP, Python, Django,
Node.js, MySQL, MariaDB, PostgreSQL, Redis, Memcached, certbot — with one plain-English request:

```
$ bastion ask "install redis"
◆ bastion · prod · claude-sonnet-4-6
Checking whether redis is already installed.
• package_status  package=redis  ✔ summary: missing redis-server  (0.1s)
redis-server is not installed. I will install the catalog entry redis (apt package redis-server).
╭─────────────────────────── Proposed action ───────────────────────────╮
│ sudo systemd-run --wait --pipe --collect --quiet                      │
│   --setenv=DEBIAN_FRONTEND=noninteractive --unit=bastion-apt-update   │
│   /usr/bin/apt-get update -q                                          │
│ sudo systemd-run --wait --pipe --collect --quiet                      │
│   --setenv=DEBIAN_FRONTEND=noninteractive                             │
│   --unit=bastion-apt-install-redis /usr/bin/apt-get install -y        │
│   redis-server                                                        │
╰─────────────────────────────────── risk: ADMIN · needs approval ──────╯
Approve? [y/N/explain] (n): y
• install_package  package=redis  ✔ summary: all installed  (41.3s)
✔ package_status: missing redis-server → all installed
• service_status  service=redis-server  ✔ is-active: active  (0.1s)
╭──────────────────────────────── Diagnosis ─────────────────────────────╮
│ Installed redis-server 5:7.0.15-1 from the catalog; the redis-server   │
│ unit is active.                                                        │
╰────────────────────────────────────────────────────────────────────────╯
```

*(Illustrative session; timings and versions depend on the host.)*

The install goes through the same gates as every other write: the model picks a **catalog key**,
the executor validates it against a closed enum, the exact commands are shown, a human types `y`,
the executor requires the SHA-256 of that displayed plan on `/run`, and the whole thing lands in the
hash-chained audit log.

---

## The catalog

The catalog is code (`bastion/tools/packages.py`), not configuration. Each key maps to a fixed list
of Debian/Ubuntu apt packages; the model can only ever name a key.

| Key | apt packages installed | systemd unit afterwards |
|---|---|---|
| `nginx` | `nginx` | `nginx` |
| `apache` | `apache2` | `apache2` |
| `php` | `php-fpm php-cli php-mysql php-pgsql php-curl php-mbstring php-xml php-zip` | `php<ver>-fpm` (release-specific; not in the service enum) |
| `python` | `python3 python3-venv python3-pip` | – |
| `django` | `python3-django python3-venv python3-pip` | – |
| `nodejs` | `nodejs npm` | – |
| `mysql` | `mysql-server mysql-client` | `mysql` |
| `mariadb` | `mariadb-server mariadb-client` | `mariadb` |
| `postgresql` | `postgresql postgresql-contrib` | `postgresql` |
| `redis` | `redis-server` | `redis-server` |
| `memcached` | `memcached` | `memcached` |
| `certbot` | `certbot python3-certbot-nginx` | – |

Notes:

- Versions are whatever the distribution's repositories ship. There is no version argument, no
  PPA/repository argument, and no `pip`/`npm` install path.
- `mysql` (Oracle MySQL) is packaged by Ubuntu; on Debian use `mariadb`.
- `django` installs the distribution's `python3-django` for a system-wide, apt-managed Django. For a
  per-project virtualenv install, ask for `python` and create the venv yourself.
- Every unit in the third column is also in the closed service enum, so `service_status`,
  `service_logs`, and `restart_service` work on it right after the install.

To see the catalog on a live executor: `bastion tools` (as an admin with the admin risk enabled),
or `python -m bastion.tools --json | jq '.[] | select(.name=="install_package")'`.

---

## The two tools

| Tool | Risk | Approval | What runs on the host |
|---|:-:|:-:|---|
| `package_status(package)` | 🟢 read | – | `dpkg-query -W -f '${binary:Package}\t${Version}\t${db:Status-Status}\n' <pkgs>` — no sudo |
| `install_package(package)` | 🔴 admin | ✋ yes | `sudo systemd-run … /usr/bin/apt-get update -q`, then `sudo systemd-run … /usr/bin/apt-get install -y <pkgs>`, then `package_status` again |

`install_package` returns the tail of apt's output for both commands, the exit code, and a fresh
`package_status` block. Success means the result ends with `summary: all installed`. After a
successful run the CLI re-runs `package_status` automatically (`verify_with`) and prints the
before/after line.

Exact plan strings for every tool: [TOOLS.md](TOOLS.md).

---

## Enabling installs on an executor

A fresh install exposes read-only tools only. Package installation is an **admin** action, so two
things must be true:

1. `/etc/bastion/config.yaml` lists the admin risk level:

   ```yaml
   enabled_risks: [read, write, admin]
   ```

   then `sudo systemctl restart bastion-executor`.

2. The token you use has `role: admin`. `operator` and `viewer` tokens never see `install_package`
   in `GET /tools`; a request with such a token gets `403 policy_denied`.

Until both hold, the model is told the tool does not exist and will say so.

`package_status` is a read tool and is available to every role from the start.

Installs can take minutes (`mysql-server` is the slow one). The executor allows 180 s for
`apt-get update` and 600 s for `apt-get install`; the CLI waits up to 900 s for a `/run`. If your
`max_seconds` loop budget is the default 120 s, the loop will still finish the install (the budget is
checked between calls) but may stop before the final summary; use `--max-seconds 600` for install
sessions.

---

## What it can never do

These are not disabled; the code paths do not exist and the sudoers file has no rule for them.

| Never | Why it is impossible |
|---|---|
| Remove, purge, autoremove, or downgrade a package | No such tool; no sudoers rule; the adversarial suite asserts every `systemd-run` argv reaching sudo is one of the catalog's exact install/update argvs |
| Install a package outside the catalog | `package` is a closed `Literal` enum; `"vim"`, `"nginx redis"`, `"nginx=1.24"` are all `422 validation_failed` |
| Pass apt flags, pin a version, add a PPA or key | The tool has one argument; extra fields are rejected (`extra="forbid"`); each sudoers line is literal, no wildcards |
| `pip install` / `npm install` | No tool; `python`/`nodejs` install the toolchains only |
| Run as `operator` or `viewer` | `install_package` is `risk="admin"`, granted to the `admin` role only |
| Run without a human | `/run` demands the SHA-256 of the plan the CLI displayed; `--dry-run` never sends it |

---

## How it runs: `systemd-run`, not the executor's own shell

The executor runs under `ProtectSystem=strict`: the entire filesystem is read-only to it except
`/var/log/bastion`. `apt-get` cannot run there. Rather than widen the sandbox, `install_package`
asks PID 1 to run apt in a **transient unit**:

```
sudo systemd-run --wait --pipe --collect --quiet \
     --setenv=DEBIAN_FRONTEND=noninteractive \
     --unit=bastion-apt-install-redis \
     /usr/bin/apt-get install -y redis-server
```

- `--wait --pipe` makes it synchronous: the executor sees apt's stdout/stderr and exit code.
- `--collect` unloads the transient unit afterwards even if apt failed.
- `--unit=bastion-apt-install-<key>` names it, so `journalctl -u bastion-apt-install-redis` shows the
  full apt log later, and two installs of the same key cannot overlap.
- `--setenv=DEBIAN_FRONTEND=noninteractive` stops debconf from prompting.

The executor's sandbox is unchanged (`deploy/bastion-executor.service` is byte-for-byte the same
apart from a comment); the transient unit is a normal root process outside it, exactly as if an
administrator had run apt by hand.

## sudoers

`deploy/sudoers.bastion` gains one `Cmnd_Alias BASTION_APT` block: one literal line for
`apt-get update -q` and one per catalog entry, generated from the very argv the tool executes:

```bash
python -m bastion.tools --sudoers-apt [/path/to/systemd-run]
```

`scripts/install.sh` runs that command with the host's real `systemd-run` path, validates the
result with `visudo -cf`, and installs it. A test asserts the committed `deploy/sudoers.bastion`
matches the renderer byte for byte, so the catalog, the tool, and the sudoers file cannot drift.
The `\=` sequences in the file are sudoers escaping (`=`, `,`, `:` must be escaped inside command
arguments); sudo compares the literal string.

---

## Extending the catalog

1. Add the key to `Package`/`PACKAGES` in `bastion/tools/_types.py` and the apt package tuple to
   `CATALOG` (and its unit, or `None`, to `CATALOG_SERVICES`) in `bastion/tools/packages.py`.
2. If it provides a unit, add the unit to `Service`/`SERVICES` in `_types.py` and a
   `systemctl restart <unit>` line to both `deploy/sudoers.bastion` and `scripts/install.sh`.
3. Regenerate the sudoers block into `deploy/sudoers.bastion`
   (`python -m bastion.tools --sudoers-apt`) and the tool docs
   (`python -m bastion.tools --docs > docs/TOOLS.md`).
4. Mention the key in the install playbook in `bastion/agent/prompts.py` and in the table above.
5. `pytest` — the catalog/enum/sudoers consistency tests will tell you what you missed.

Do not add: anything that takes a path, a URL, or a version; anything that removes; anything that
is not an apt package.
