Entry private overlays are applied after the public `base-entry` bundle is rendered.

Use this directory for:

- private `xray.merge.json` patches for Entry-side `Xray`
- full replacements of `haproxy.cfg`, `nginx.conf`, `nftables.conf`
- optional private static/auth content under `decoy/`

Do not store the actual packet-splitting or host fingerprinting algorithm in the public repository.
