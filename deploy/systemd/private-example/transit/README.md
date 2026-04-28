Transit private overlays are applied after the public `base-transit` bundle is rendered.

Use this directory for:

- private `xray.merge.json` patches for Transit-side `Xray`
- full replacements of `haproxy.cfg`, `nginx.conf`, `nftables.conf`
- optional private static/auth content under `decoy/`

If you later move UDP profiles to `Xray`-native transports, this is the place for `FinalMask` or `ECH` fragments that must remain off-repo.
