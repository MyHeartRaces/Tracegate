# Secrets & Cryptography

How Tracegate handles secrets at rest, in transit to the data plane, and the
cryptographic primitives used for authn, signing, and pseudonymity.

## 1. Repository boundary

- **Public repo** (`Tracegate`): source, tests, generic chart, placeholder
  values, generic validators. Public examples use placeholders, loopback, or
  documentation-reserved ranges.
- **Private repo** (`tracegate-private`): deployment package, operator docs,
  **SOPS-encrypted** manifests, private metadata.

Never committed (verified via `git ls-files`): plaintext tokens/passwords/keys,
MTProto secrets, decrypted values, generated client links/configs, kubeconfigs,
TLS private material, rendered live manifests, user-grant runtime state. Only
SOPS-encrypted `.sops.yaml` and `.example` files are tracked; on-disk certs /
kubeconfigs in `runtime-local/` are git-ignored.

## 2. Secret-at-rest: SOPS + age

`tracegate-private/.sops.yaml` defines creation rules keyed to one age recipient
(public key is safe to commit). `encrypted_regex: ^(data|stringData)$` keeps
`apiVersion`/`kind`/`metadata` readable while encrypting only Secret payloads.
Helper scripts: `init-age.sh`, `sops-encrypt-file.sh`, `sops-edit.sh`,
`verify-encrypted.sh`, and `apply-k8s-secrets.sh` (decrypt → `kubectl apply`,
refuses `.example` files).

Finding **F10**: a single age recipient means recovery depends on one identity —
keep an offline backup and consider a break-glass recipient.

> The architecture intentionally drops the legacy LUKS runtime guard; disk-at-rest
> exposure is accepted. Confidentiality rests on "never commit/print secrets,"
> not node disk encryption.

## 3. Secret injection into the data plane

The gateway pod's `seed-runtime` init container reads the mounted private-profile
Secret and replaces `REPLACE_*` placeholders in the base configs via `sed`
(Reality private key, SS-2022 password, Salamander password, Hysteria stats
secret, VLESS encryption, MTProto secret, etc.). The MTProto secret is validated
(16 bytes / 32 hex). The `validate-private-profiles` init container (preflight)
fails closed if a required key is missing or still a placeholder
(`forbidPlaceholders`).

## 4. Control-plane authentication

`src/tracegate/security.py`:

- **Bootstrap token** (`api_internal_token`) → grants the `all` scope.
- **DB-issued API tokens** → SHA-256 hashed and matched in SQL; carry scopes
  (`<area>:read|write|rw` or `all`). `_scope_matches` expands `:rw` to read+write.
- **Agent token** (`agent_auth_token`) → gates the agent control channel.

All shared-secret comparisons are **constant-time** (`hmac.compare_digest`) after
finding **F1** — previously the bootstrap and agent tokens used plain `==`/`!=`.

Tokens default to empty in `settings.py` (must be provided by the operator); the
chart wires them from Kubernetes Secrets (`API_INTERNAL_TOKEN`, `AGENT_AUTH_TOKEN`,
stats secret, etc.).

## 5. HMAC-signed artefacts

| Artefact | Where | Construction |
|----------|-------|--------------|
| Client-config tokens | `services/client_config_tokens.py` | HMAC-SHA256 over payload, base64url, expiring |
| Decoy session cookie | `services/decoy_auth.py` | HMAC-SHA256 `payload.sig`, `compare_digest` verify |
| Grafana OTP/handoff | `api/routers/grafana.py` | HMAC-SHA256, `compare_digest` verify |
| Pseudonym aliases | `services/pseudonym.py` | HMAC-SHA256 from `pseudonym_secret` (fallbacks: grafana cookie secret, api token) |

Decoy credentials are compared with `hmac.compare_digest` (login **and**
password). The decoy cookie secret falls back across `pseudonym_secret` →
`grafana_cookie_secret` → `api_internal_token` → `agent_auth_token`.

## 6. Pseudonymity

Personal alias tokens are HMAC-derived from a private pseudonym secret and must
not expose raw connection IDs or Telegram IDs. Rotating `pseudonym_secret` changes
all generated aliases and therefore requires a controlled client migration. This
is **separation, not anonymity** — provider-level observers still see ownership
and routing relationships.

## 7. Transport key material

- **Reality**: per-role private keys (`realityPrivateKeyEntry/Transit`) in the
  Secret; only public keys + shortIds reach clients.
- **Hysteria2**: Salamander password + stats secret + (optional) backhaul auth
  token, all per-role in the Secret.
- **SS-2022 / ShadowTLS**: static node-side outer credentials in the Secret;
  SS-2022 user keys are per-connection.
- **WireGuard**: server private key in the Secret; server public key is
  client-safe.
- **MTProto**: 16-byte secret in the Secret, validated at seed time.

## 8. Secret lifecycle (operator)

Generate high-entropy independent secrets per purpose; store as SOPS manifests;
keep age identity backups offline; rotate compromised credentials immediately;
rotate transport material with an overlap plan when clients must update; revoke
individual user/device/MTProto grants through control-plane APIs (zero-restart).
See the private [deploy/secrets audit](../../.. "tracegate-private/docs/audit").
