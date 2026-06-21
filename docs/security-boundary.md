# Security Boundary

This repository is safe to publish only while it stays limited to source code,
safe examples and high-level documentation.

## Allowed In Public Git

- application source code;
- public templates with placeholders;
- migrations and tests;
- safe `.example` configuration;
- documentation that describes workflows without live deployment details.

## Keep Private

- real domains, addresses and endpoint layout;
- exact production ports and host policy;
- node inventory, aliases and provider metadata;
- decrypted Kubernetes Secrets;
- plaintext disk encryption keys, LUKS passphrases and unencrypted LUKS header
  backups;
- production values files;
- rendered manifests built from production values;
- raw client exports and import links;
- decoy site HTML/CSS/JS;
- live deployment wrappers or promotion scripts;
- operational notes that make the live system easier to fingerprint.

## Documentation Rule

Public docs can explain what an operator should do. They should not explain
where the live service is, how traffic is externally shaped, or which exact
production paths and endpoints are active.

When in doubt, write the general procedure here and put the concrete production
value in the private deployment repository.

Disk encryption keys are stricter than normal deployment values: a private
repository may store only encrypted backup material, never plaintext unlock
secrets. Keep the decrypting identity in a password manager, hardware token,
operator vault or KMS outside Git. See `docs/node-encryption-runbook.md`.
