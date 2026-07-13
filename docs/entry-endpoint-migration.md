# Entry and Endpoint host migration

Promote Endpoint first, validate direct and backup transports, then promote
Entry and validate Chain and Telegram Proxy. Each host uses a separate private
role overlay, immutable image digest and release directory.

Keep the previous runtime active until the new role passes `/ready`, agent
health and sustained payload probes. Do not enable new bot issuance before its
server runtime and revocation path have both been verified.
