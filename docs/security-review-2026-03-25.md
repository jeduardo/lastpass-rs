# Security Review -- lastpass-rs

**Date:** 2026-03-25
**Scope:** All Rust source code under `src/`. Excludes `lastpass-cli/` (upstream C reference) and all test code.
**Tools used:** Manual source review, `cargo audit`, `cargo outdated` (failed -- see notes).

---

## 1. Executive Summary

The codebase has strong security fundamentals: `#![forbid(unsafe_code)]` on every module, encrypted-at-rest config storage with authenticated encryption (HMAC-SHA256 + AES-256-CBC), proper Unix file permissions (`0o600`/`0o700`), and `rustls` instead of OpenSSL. The main gaps are around memory hygiene for decrypted secrets, transitive dependency vulnerabilities, and silent error handling in cleanup paths.

---

## 2. Dependency Vulnerability Audit (`cargo audit`)

Seven advisories were found. All are transitive (pulled in by `reqwest` or `rsa`).

| Crate | Version | Advisory | Severity | Fix |
|---|---|---|---|---|
| `aws-lc-sys` | 0.38.0 | RUSTSEC-2026-0044 -- X.509 Name Constraints bypass | -- | Upgrade to >= 0.39.0 |
| `aws-lc-sys` | 0.38.0 | RUSTSEC-2026-0048 -- CRL Distribution Point logic error | 7.4 (high) | Upgrade to >= 0.39.0 |
| `bytes` | 1.11.0 | RUSTSEC-2026-0007 -- Integer overflow in `BytesMut::reserve` | -- | Upgrade to >= 1.11.1 |
| `quinn-proto` | 0.11.13 | RUSTSEC-2026-0037 -- DoS in Quinn endpoints | 8.7 (high) | Upgrade to >= 0.11.14 |
| `rsa` | 0.9.10 | RUSTSEC-2023-0071 -- Marvin Attack timing sidechannel | 5.9 (medium) | **No fix available in 0.9.x** |
| `rustls-webpki` | 0.103.9 | RUSTSEC-2026-0049 -- CRL matching logic error | -- | Upgrade to >= 0.103.10 |
| `time` | 0.3.46 | RUSTSEC-2026-0009 -- DoS via stack exhaustion | 6.8 (medium) | Upgrade to >= 0.3.47 |

**Impact assessment:**
- `aws-lc-sys`, `rustls-webpki`: Affect TLS certificate validation. An attacker with a malicious certificate could potentially bypass name constraints or CRL checks during HTTPS communication with LastPass servers. Risk is limited because the client only connects to `lastpass.com`.
- `bytes`: Integer overflow in buffer reservation. Exploitable only with very large HTTP response bodies.
- `quinn-proto`: DoS via QUIC. Only relevant if reqwest uses HTTP/3 (currently unlikely for LastPass API traffic).
- `rsa` (Marvin Attack): Timing sidechannel during RSA decryption could theoretically allow key recovery. This crate is used for shared folder key decryption. No fix exists in the 0.9.x line.
- `time`: Stack exhaustion parsing malformed input. Used in timestamp formatting; input is controlled (Unix timestamps from API).

## 3. Dependency Freshness

`cargo outdated` failed to run due to a resolution conflict between `rand 0.8` (pinned) and `rand 0.10` (latest). Versions noted from `Cargo.lock`:

| Crate | Locked | Latest line | Notes |
|---|---|---|---|
| `rand` | 0.8.5 | 0.9.x / 0.10.x | API breaking changes in 0.9; `getrandom` feature syntax changed |
| `thiserror` | 1.0.69 | 2.x | v2 available, non-urgent |
| `reqwest` | 0.12.28 | 0.12.x current | `rustls-tls` feature obsolete in 0.13+ |
| `rsa` | 0.9.10 | 0.9.x current | No 0.10 line exists; Marvin Attack advisory has no fix |
| All others | Current | -- | Up to date within their major version lines |

---

## 4. Cryptographic Review

### 4.1 Authenticated encryption (local config storage) -- GOOD

`src/crypto.rs:29-77` -- Encrypt-then-MAC using AES-256-CBC + HMAC-SHA256. IV is generated from `OsRng`. HMAC covers IV + ciphertext. Verification uses constant-time `verify_slice()`. This is correct.

### 4.2 RSA-OAEP with SHA-1 -- PROTOCOL CONSTRAINT

`src/crypto.rs:152-167` -- Both `rsa_decrypt_oaep` and `rsa_encrypt_oaep` use `Oaep::new::<Sha1>()`. SHA-1 in OAEP is not directly exploitable (OAEP security does not rely on collision resistance), but it is a deprecated hash. This matches the LastPass protocol and cannot be changed unilaterally.

### 4.3 AES-ECB for legacy entries -- PROTOCOL CONSTRAINT

`src/crypto.rs:183-193` -- `aes_decrypt_lastpass_legacy_ecb` uses AES-ECB, which leaks patterns in identical plaintext blocks. This exists for backward compatibility with old vault entries. The C client has the same code path.

### 4.4 PBKDF2 minimum iterations -- GOOD

`src/kdf.rs:13` -- `MINIMUM_ITERATIONS = 2`. Both `kdf_login_key` and `kdf_decryption_key` reject iterations < 2. The server-side iteration count is fetched and validated.

### 4.5 Random number generation -- GOOD

All crypto-random operations use `OsRng` (`rand::rngs::OsRng`), which delegates to the OS CSPRNG. No use of weak PRNGs for security-sensitive operations.

---

## 5. Memory Hygiene

### 5.1 FINDING: Decrypted vault data in `Account` struct is never zeroized

**Severity: HIGH**
**Files:** `src/blob.rs:19-49`, all commands that call `load_blob()`

The `Account` struct holds plaintext `password`, `username`, `note`, `url`, and `attachkey` as plain `String` fields. These are never zeroized. Once the blob is parsed, plaintext secrets persist in heap memory until process exit. A core dump, swap-to-disk, or memory-scanning attack could extract them.

### 5.2 FINDING: Incomplete zeroization of decryption key buffers

**Severity: HIGH**
**File:** `src/agent.rs:37-56`

In `agent_get_decryption_key()`, when reading a valid `plaintext_key` file, the intermediate `buffer: Vec<u8>` from `config_read_buffer` is not zeroized. The `agent_is_available()` function (lines 65-85) correctly zeroizes in some paths but not others. Zeroization should be applied consistently to all intermediate key-holding buffers.

### 5.3 FINDING: `plaintext_key` stores raw decryption key on disk

**Severity: HIGH (intentional -- matches C client)**
**File:** `src/commands/login.rs:92-93`

When `--plaintext-key` is used, the raw 32-byte decryption key is written to disk. The confirmation prompt matches the C client behavior. File permissions are `0o600`.

**C client parity:** Verified. The C client (`cmd-login.c`) has identical behavior with the same `--plaintext-key` flag and confirmation prompt.

---

## 6. Data Integrity and Destructive Operations

### 6.1 `rm` -- No confirmation prompt

**Severity: MEDIUM (informational)**
**File:** `src/commands/rm.rs:84-87`

The `rm` command permanently removes an account from the local blob and enqueues a server-side deletion with no interactive confirmation.

**C client parity:** Verified. `cmd-rm.c` has no confirmation prompt, no `--force` flag, and no y/n question. The Rust implementation matches the C behavior exactly.

### 6.2 `mv` -- No confirmation prompt

**Severity: LOW (informational)**
**File:** `src/commands/mv.rs:81-96`

The `mv` command moves entries between groups/shared folders without confirmation.

**C client parity:** Verified. `cmd-mv.c` has no confirmation prompt. Matches exactly.

### 6.3 `edit` -- No overwrite confirmation

**File:** `src/commands/edit.rs`

The `edit` command overwrites entry data directly.

**C client parity:** Verified. `cmd-edit.c` has no confirmation before overwriting. Matches exactly.

### 6.4 `add` -- No duplicate detection

**File:** `src/commands/add.rs`

The `add` command creates a new entry without checking for duplicates.

**C client parity:** Verified. `cmd-add.c` does not check for existing entries with the same name. Matches exactly.

### 6.5 `import` -- No bulk confirmation, silent deduplication

**File:** `src/commands/import.rs`

Import reads CSV, silently removes duplicates (unless `--keep-dupes`), and uploads without a y/n prompt.

**C client parity:** Verified. `cmd-import.c` has the same behavior -- deduplication is silent, no confirmation prompt. Matches exactly.

### 6.6 `logout` -- Has confirmation prompt

**File:** `src/commands/logout.rs`

The `logout` command prompts "Are you sure you would like to log out?" unless `--force` is used.

**C client parity:** Verified. `cmd-logout.c` calls `ask_yes_no(true, ...)` with the same prompt text, defaulting to yes. `--force` skips the prompt. Matches exactly.

### 6.7 FINDING: `mv` removes account from local blob before save completes on share moves

**Severity: MEDIUM**
**File:** `src/commands/mv.rs:85-89`

When moving between shared folders, the API call (`maybe_push_account_share_move`) is made first, then the account is removed from the local blob, then `save_blob()` is called. If `save_blob()` fails after the API call succeeds, local and remote state diverge.

**C client parity:** The C client has a similar ordering -- API call followed by local save. This is a structural risk inherited from the original design.

### 6.8 FINDING: `session_kill()` silently ignores all file deletion errors

**Severity: MEDIUM**
**File:** `src/session.rs:118-140`

All `unlink()` calls use `let _ =` to discard errors. If session files cannot be deleted, the user is not warned and may believe they have logged out when sensitive data remains on disk.

**C client parity:** Verified. The C `session_kill()` in `session.c` also ignores `unlink()` return values. `config_unlink()` in `config.c` returns a bool but the caller never checks it. The Rust code matches the C behavior exactly.

### 6.9 FINDING: Upload queue silently moves failed requests to `upload-fail/` directory

**Severity: MEDIUM**
**File:** `src/upload_queue.rs`

After `MAX_RETRIES` (5 in release), failed uploads are moved to a fail directory. The user is never notified that their vault modification did not sync to the server.

**C client parity:** The C client has a similar upload queue mechanism with the same silent failure behavior.

---

## 7. Input Handling

### 7.1 FINDING: `from_utf8_lossy` may silently corrupt re-uploaded data

**Severity: MEDIUM**
**Files:** `src/blob.rs:100,203,277,459,468,482`

`String::from_utf8_lossy` replaces invalid UTF-8 bytes with U+FFFD. If decrypted data contains invalid UTF-8 (wrong key, corrupted data), the replacement characters are silently inserted. If that corrupted string is then re-encrypted and uploaded (via `edit`, `mv`, `add`), the original data is permanently destroyed.

### 7.2 Clipboard command injection via `LPASS_CLIPBOARD_COMMAND` -- BY DESIGN

**File:** `src/commands/clipboard.rs:52-59`

`LPASS_CLIPBOARD_COMMAND` is passed to `sh -c` with secret data on stdin. This matches the C client behavior and assumes the user controls their own environment.

### 7.3 Log file content -- LOW RISK

**File:** `src/logging.rs:7-28`, `src/http.rs:93,108`

HTTP page names are logged at level 5 (e.g., `login.php`). No credentials are logged. Log file has `0o600` permissions via the config store.

---

## 8. Network Security

### 8.1 HTTPS only -- GOOD

**File:** `src/http.rs:137,164`

All requests use `https://` URLs. No HTTP fallback exists.

### 8.2 Session cookie handling -- GOOD

**File:** `src/http.rs:189-199`

Session ID is sent via `Cookie: PHPSESSID=...` header only when a session is available. No credential leakage in URLs.

### 8.3 No certificate pinning -- INFORMATIONAL

The client relies on system/rustls CA trust store. No LastPass-specific certificate pinning. Same as C client.

---

## 9. Agent Security

### 9.1 Peer validation -- GOOD

**File:** `src/agent.rs:356-376`

The agent validates connecting clients by checking UID and GID match the agent's own identity. On Linux this uses `SO_PEERCRED`; on macOS it uses `getpeereid()`. This prevents other users from extracting the key.

### 9.2 Socket permissions -- GOOD

**File:** `src/agent.rs:236`

Agent socket is created with `0o600` permissions.

### 9.3 No rate limiting on key distribution -- LOW

**File:** `src/agent.rs:245-260`

Any same-user process can connect and retrieve the key without rate limiting or logging.

**C client parity:** The C agent has the same behavior.

---

## 10. Mitigation Plan

### Priority 1 -- Dependency vulnerabilities (fix immediately) -- FIXED 2026-03-25

**Action:** Run `cargo update` to pull patched transitive dependencies.

Target fixes:
- `aws-lc-sys` >= 0.39.0 (RUSTSEC-2026-0044, RUSTSEC-2026-0048) -- FIXED
- `bytes` >= 1.11.1 (RUSTSEC-2026-0007) -- FIXED
- `quinn-proto` >= 0.11.14 (RUSTSEC-2026-0037) -- FIXED
- `rustls-webpki` >= 0.103.10 (RUSTSEC-2026-0049) -- FIXED
- `time` >= 0.3.47 (RUSTSEC-2026-0009) -- FIXED

**Cannot fix:** `rsa` 0.9.10 Marvin Attack (RUSTSEC-2023-0071) -- no patched version exists. Monitor for updates.

**Effort:** Low (single `cargo update` + CI pass).

### Priority 2 -- Memory hygiene for vault secrets (high impact) -- FIXED 2026-03-25

**Action:** Wrap sensitive `Account` fields in `Zeroizing<String>` from the `zeroize` crate (already a dependency).

**Files modified:**
- `Cargo.toml` -- Enabled `serde` feature on `zeroize`
- `src/blob.rs` -- Changed `password`, `username`, `note`, `attachkey` fields to `Zeroizing<String>`
- `src/agent.rs` -- Zeroize intermediate `Vec<u8>` buffers in `agent_get_decryption_key()` after copying to fixed-size array
- All command files, test files, mock files updated to use `Zeroizing::new()` for struct construction

**Effort:** Medium. Required updating all consumers of `Account` fields.

### Priority 3 -- Replace `from_utf8_lossy` in re-upload paths (data safety) -- FIXED 2026-03-25

**Action:** In blob parsing paths where data may be re-uploaded to the server, replaced `String::from_utf8_lossy` with `String::from_utf8` and propagated the error. Kept `from_utf8_lossy` only for display-only paths (version string, share name, chunk tags).

**Files modified:**
- `src/blob.rs` -- `read_plain_string` (returns `InvalidUtf8` error), `read_hex_string` (returns `InvalidUtf8` error), `read_crypt_string` (falls back to empty string on UTF-8 failure, preserving encrypted form for re-upload)

### Priority 4 -- Upgrade `rand` to 0.9.x (housekeeping) -- BLOCKED

**Status:** Cannot upgrade. The `rsa` crate 0.9.x depends on `rand_core` 0.6, which is incompatible with `rand` 0.9 (which uses `rand_core` 0.9). `OsRng` from rand 0.9 does not implement the `CryptoRngCore` trait from rand_core 0.6 that `rsa` expects. No version of `rsa` currently supports rand 0.9. This upgrade is blocked until `rsa` releases a compatible version.

**Effort:** N/A -- dependency conflict.

### Priority 5 -- Upgrade `thiserror` to v2 (housekeeping) -- FIXED 2026-03-25

**Action:** Updated `thiserror` from 1.x to 2.x in `Cargo.toml`. No code changes required -- fully backward compatible.

**Effort:** Low.

### Not planned (matches C client by design)

The following behaviors match the C client exactly and are **not** recommended for change, to preserve drop-in compatibility:

- No confirmation prompt on `rm`, `mv`, `edit`, `add`, `import`
- `plaintext_key` file storage with `--plaintext-key` flag
- Clipboard command injection via `LPASS_CLIPBOARD_COMMAND`
- RSA-OAEP with SHA-1
- AES-ECB legacy decryption path
- Silent `session_kill()` error handling
- Silent upload queue failure handling (files moved to `upload-fail/` without user notification)
- Agent key distribution without rate limiting

---

## Appendix: Files Reviewed

```
src/main.rs          src/lib.rs           src/agent.rs
src/blob.rs          src/cli.rs           src/config.rs
src/crypto.rs        src/editor.rs        src/error.rs
src/format.rs        src/http.rs          src/kdf.rs
src/logging.rs       src/lpenv.rs         src/notes.rs
src/password/mod.rs  src/session.rs       src/share.rs
src/terminal.rs      src/upload_queue.rs  src/util.rs
src/version.rs       src/xml.rs
src/commands/mod.rs  src/commands/add.rs  src/commands/argparse.rs
src/commands/clipboard.rs                 src/commands/data.rs
src/commands/duplicate.rs                 src/commands/edit.rs
src/commands/export.rs                    src/commands/generate.rs
src/commands/import.rs                    src/commands/login.rs
src/commands/logout.rs                    src/commands/ls.rs
src/commands/mv.rs   src/commands/passwd.rs
src/commands/rm.rs   src/commands/share.rs
src/commands/show.rs src/commands/status.rs
src/commands/sync.rs
build.rs             Cargo.toml           Cargo.lock
```

C reference files consulted for behavior parity verification:
```
lastpass-cli/cmd-rm.c      lastpass-cli/cmd-mv.c
lastpass-cli/cmd-edit.c    lastpass-cli/cmd-add.c
lastpass-cli/cmd-import.c  lastpass-cli/cmd-logout.c
lastpass-cli/session.c     lastpass-cli/config.c
lastpass-cli/agent.c
```
