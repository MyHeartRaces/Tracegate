# Running Tracegate without k3s or Helm

The current supported production contract is the Helm chart on k3s. Running
without both components is possible only after translating the Deployments,
ConfigMaps, Secrets, probes, host networking, persistent volumes and nftables
units into another supervisor such as systemd or Docker Compose. That is a new
deployment target, not a switch in the existing installer.

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

## Required replacements

A non-k3s package must preserve the chart's invariants: host-network port
ownership, loopback-only backend listeners, Entry/Endpoint source ACLs,
generated runtime state, atomic hot reloads, persistent PostgreSQL and gateway
state, TLS/secret file permissions, health probes, nftables policies and
ordered rollouts. Until those are implemented and tested, the non-k3s sizing
figures are capacity guidance rather than a supported installation method.
