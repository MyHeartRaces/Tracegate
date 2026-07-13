# Tracegate host sizing

The supported production contract is a Linux host with systemd, Docker and
host networking. Entry and Endpoint remain separate runtime roles.

## Capacity floor

For a small installation with the control plane, PostgreSQL, bot, both gateway
roles and Prometheus/Grafana on one host:

- hard floor: 2 vCPU, 4 GiB RAM and 40 GiB SSD;
- practical baseline: 4 vCPU, 8 GiB RAM and 60 GiB SSD;
- without Prometheus and Grafana: 2 vCPU and 2 GiB can run a low-traffic
  installation, but leaves little safe rollout or traffic-burst headroom.

For the production two-host topology:

- Entry: 1 vCPU and 1 GiB is the tested floor; 2 GiB is safer;
- Endpoint plus control plane: 2 vCPU and 4 GiB is the floor; 4 vCPU and 8 GiB
  is the practical baseline when monitoring is enabled.

Network quality and committed throughput usually limit a proxy gateway before
idle CPU does. Size from concurrent throughput, connection rate and Hysteria2
UDP load, and keep at least 30 percent RAM headroom for restarts and upgrades.

## Required invariants

The host package must preserve port ownership, loopback-only backend listeners,
Entry/Endpoint source ACLs, generated runtime state, atomic hot reloads,
persistent PostgreSQL and gateway state, TLS/secret file permissions, health
checks, nftables policies and ordered rollouts. Run `make host-check` before
packaging or rollout.
