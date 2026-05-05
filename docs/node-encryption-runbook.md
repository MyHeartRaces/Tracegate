# Entry and Transit Node Encryption Runbook

This runbook describes how to prepare encrypted runtime storage for Tracegate
Entry and Transit nodes. Endpoint nodes can stay unchanged until endpoint
runtime encryption is explicitly enabled.

The Helm chart does not unlock disks and must not receive the disk key. It only
checks that the selected Entry and Transit nodes expose the expected encrypted
runtime marker before gateway pods start.

K3s/Kubernetes Secrets encryption is a separate control for API datastore
objects. It is useful and should be enabled for cluster Secrets, but it does
not encrypt `/var/lib/tracegate/entry` or `/var/lib/tracegate/transit`.

## Security Model

- Do not store a plaintext LUKS passphrase or keyfile in public Git, private
  Git, Helm values, Kubernetes Secrets, rendered manifests or endpoint nodes.
- A private repository is acceptable only for encrypted backup material, for
  example a SOPS, age or GPG encrypted file whose decrypting identity is stored
  outside that repository.
- Store the live recovery secret in a password manager, hardware token,
  operator vault or cloud KMS that is not readable by the cluster. If a
  repo-local operator copy is needed, keep it only under `.tracegate-secrets/`,
  which is ignored by Git.
- Prefer manual unlock or TPM/KMS-backed unlock. Do not use a plaintext keyfile
  left on the same server root disk; that mostly defeats snapshot-at-rest
  protection.
- Back up the LUKS header after formatting. Without the header and unlock
  secret, the data is unrecoverable.
- This protects data at rest. It does not hide a running VM from a provider
  with hypervisor or live memory access.

## Choose the Storage

Use a separate block device or provider volume for runtime state. Do not format
the root disk from this procedure.

Per role, the chart expects these host paths:

```text
/var/lib/tracegate/entry
/var/lib/tracegate/transit
```

If Entry and Transit are on different nodes, provision one encrypted volume on
each node. If a node can run both roles, either use one encrypted filesystem
mounted at `/var/lib/tracegate` or separate encrypted mounts for each role.

## Create the Unlock Secret

Run this from the repository root on an operator machine, not inside the
cluster. The `.tracegate-secrets/` directory is ignored by Git.

```bash
umask 077
SECRET_DIR="${PWD}/.tracegate-secrets/luks"
mkdir -p "${SECRET_DIR}"

ROLE=entry
KEYFILE="${SECRET_DIR}/tracegate-${ROLE}-runtime.luks-key"

openssl rand -base64 48 | tr -d '\n' > "${KEYFILE}"
chmod 0400 "${KEYFILE}"
```

Immediately save the key value in a password manager or vault record named
similar to:

```text
tracegate/luks/entry-01/runtime-state
```

If a private repository is used for backup, commit only an encrypted copy:

```bash
gpg --symmetric --cipher-algo AES256 \
  --output "${KEYFILE}.gpg" \
  "${KEYFILE}"
```

Keep the repo-local plaintext copy only if this workstation is the intended
operator unlock source. Otherwise, after the value is safely stored outside
Git, remove the local plaintext copy:

```bash
shred -u "${KEYFILE}"
```

Repeat the same process for each Transit node with `ROLE=transit`.

## Format and Mount a LUKS Volume

Run the following on the target Entry or Transit server. Replace `DEVICE` with
the dedicated block device path, not the root disk.

```bash
ROLE=entry
DEVICE=/dev/disk/by-id/REPLACE_WITH_DEDICATED_VOLUME
MAP_NAME="tracegate-${ROLE}-state"
MOUNT_PATH="/var/lib/tracegate/${ROLE}"
KEYFILE=/root/tracegate-luks.key
```

For an existing node, first stop writes to the role runtime directory from the
operator environment during a maintenance window:

```bash
kubectl cordon NODE_NAME
kubectl -n tracegate scale deploy -l app.kubernetes.io/component=gateway-entry --replicas=0
```

Use `gateway-transit` instead of `gateway-entry` for a Transit node. If the
directory already contains state that must be preserved, copy it before
mounting the encrypted filesystem:

```bash
sudo install -d -m 0700 /root/tracegate-runtime-backup
sudo rsync -aHAX "/var/lib/tracegate/${ROLE}/" \
  "/root/tracegate-runtime-backup/${ROLE}/"
```

Copy the keyfile to the server for the provisioning session only:

```bash
sudo install -m 0400 -o root -g root /tmp/tracegate-luks.key "${KEYFILE}"
```

Inspect before formatting:

```bash
lsblk -f "${DEVICE}"
sudo wipefs -n "${DEVICE}"
```

The next command destroys data on `DEVICE`:

```bash
sudo cryptsetup luksFormat --type luks2 "${DEVICE}" "${KEYFILE}"
sudo cryptsetup open "${DEVICE}" "${MAP_NAME}" --key-file "${KEYFILE}"
sudo mkfs.ext4 -L "${MAP_NAME}" "/dev/mapper/${MAP_NAME}"
```

Mount and write the Tracegate marker:

```bash
sudo install -d -m 0750 -o root -g root "${MOUNT_PATH}"
sudo mount "/dev/mapper/${MAP_NAME}" "${MOUNT_PATH}"
if [ -d "/root/tracegate-runtime-backup/${ROLE}" ]; then
  sudo rsync -aHAX "/root/tracegate-runtime-backup/${ROLE}/" "${MOUNT_PATH}/"
fi
printf '%s\n' 'tracegate-encrypted-runtime-v1' | \
  sudo tee "${MOUNT_PATH}/.tracegate-encrypted" >/dev/null
sudo chmod 0644 "${MOUNT_PATH}/.tracegate-encrypted"
```

Back up the LUKS header and encrypt the backup before it leaves the server:

```bash
sudo cryptsetup luksHeaderBackup "${DEVICE}" \
  --header-backup-file "/root/${MAP_NAME}.luks-header"
sudo gpg --symmetric --cipher-algo AES256 \
  --output "/root/${MAP_NAME}.luks-header.gpg" \
  "/root/${MAP_NAME}.luks-header"
sudo shred -u "/root/${MAP_NAME}.luks-header"
```

Store the encrypted header backup outside the server. Treat it as sensitive.

Remove the temporary plaintext keyfile from the server unless a TPM/KMS unlock
flow explicitly needs a host-local sealed secret:

```bash
sudo shred -u "${KEYFILE}"
```

## Boot and Unlock Options

Pick one option per node.

### Manual Unlock

This keeps the unlock secret off the server. After every reboot, an operator
opens the volume and mounts it before gateway pods can start:

```bash
ROLE=entry
DEVICE=/dev/disk/by-id/REPLACE_WITH_DEDICATED_VOLUME
MAP_NAME="tracegate-${ROLE}-state"
MOUNT_PATH="/var/lib/tracegate/${ROLE}"

sudo cryptsetup open "${DEVICE}" "${MAP_NAME}"
sudo mount "/dev/mapper/${MAP_NAME}" "${MOUNT_PATH}"
```

### TPM2 Unlock

Use this only when the server has a real TPM2 device and the recovery secret is
stored outside the server. Enroll TPM2 after formatting:

```bash
sudo systemd-cryptenroll "${DEVICE}" --tpm2-device=auto
sudo systemd-cryptenroll "${DEVICE}" --recovery-key
```

Then add `/etc/crypttab` and `/etc/fstab` entries:

```bash
DEVICE_UUID="$(sudo blkid -s UUID -o value "${DEVICE}")"
echo "${MAP_NAME} UUID=${DEVICE_UUID} none luks,tpm2-device=auto,nofail" | \
  sudo tee -a /etc/crypttab
echo "/dev/mapper/${MAP_NAME} ${MOUNT_PATH} ext4 defaults,nofail,nodev,nosuid 0 2" | \
  sudo tee -a /etc/fstab
sudo systemctl daemon-reload
```

Test the path during a controlled maintenance window before relying on reboot
automation.

### External KMS Unlock

If the provider supports KMS-backed disk unlock or an encrypted volume service,
use that instead of storing a local plaintext key. Keep the Tracegate marker and
Kubernetes annotation steps the same. If the mounted path is not backed by
dm-crypt on the node, leave `requireDeviceMapperSource=false` and document the
provider control in the private deployment repository.

## Kubernetes Node Annotation

Annotate only the nodes that have the encrypted Entry or Transit runtime path:

```bash
kubectl annotate node ENTRY_NODE_NAME tracegate.io/encrypted-runtime=true --overwrite
kubectl annotate node TRANSIT_NODE_NAME tracegate.io/encrypted-runtime=true --overwrite
```

In strict LUKS/dm-crypt deployments, set this in the private values overlay:

```yaml
gateway:
  nodeEncryption:
    enabled: true
    required: true
    requireDeviceMapperSource: true
```

Use `requireDeviceMapperSource=false` only for verified provider-managed
encrypted volumes that do not appear as `/dev/mapper/*` or `/dev/dm-*` inside
the pod mount table.

## Verification

On each Entry or Transit node:

```bash
findmnt /var/lib/tracegate/entry /var/lib/tracegate/transit
sudo cryptsetup status tracegate-entry-state || true
sudo cryptsetup status tracegate-transit-state || true
cat /var/lib/tracegate/entry/.tracegate-encrypted 2>/dev/null || true
cat /var/lib/tracegate/transit/.tracegate-encrypted 2>/dev/null || true
```

From the operator environment, run the strict deployment gate with the live
overlay and cluster preflight enabled.

If the marker or annotation is missing, Entry and Transit pods fail before
serving traffic.

If the node was cordoned and the role deployment was scaled down for migration,
restore the intended replica count after the encrypted mount is verified:

```bash
kubectl -n tracegate scale deploy -l app.kubernetes.io/component=gateway-entry --replicas=1
kubectl uncordon NODE_NAME
```

Use the Transit label and the intended replica count for Transit migrations.

## References

- cryptsetup `luksFormat`: https://www.man7.org/linux/man-pages/man8/cryptsetup-luksFormat.8.html
- cryptsetup `open`: https://man7.org/linux/man-pages/man8/cryptsetup-luksopen.8.html
- systemd `crypttab`: https://www.freedesktop.org/software/systemd/man/devel/crypttab.html
- systemd `systemd-cryptenroll`: https://www.freedesktop.org/software/systemd/man/devel/systemd-cryptenroll.html
- K3s Secrets encryption: https://docs.k3s.io/security/secrets-encryption
