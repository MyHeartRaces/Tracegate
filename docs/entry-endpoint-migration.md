# Entry and Endpoint migration

New production is promoted in two phases.

## Endpoint first

- provision Endpoint with four IPv4 addresses;
- set `architecture.deploymentPhase=endpoint-first`;
- set `architecture.podRuntimeOnly=true`;
- enable only `gateway.roles.transit`, the Endpoint compatibility role;
- use PVC gateway state and ConfigMap/PVC decoy content;
- install Endpoint ingress firewall and Endpoint egress SNAT;
- validate Direct and Backup sustained payload before continuing.

## Full

- provision one-IP Entry;
- set `architecture.deploymentPhase=full`;
- enable Universal Entry, XHTTP/REALITY primary and Hysteria2 secondary
  backhauls;
- enable MTProto client ingress through Entry while Telemt remains in the
  Endpoint pod;
- validate Endpoint-only egress and failure-closed Entry behavior.

The old deployment remains available for rollback until canary observation and
user revision migration are complete.
