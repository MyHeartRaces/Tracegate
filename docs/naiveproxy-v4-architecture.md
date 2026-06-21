# Retired NaiveProxy V4

NaiveProxy V4 was removed from the Tracegate 3 issuance and deployment
surfaces.

Tracegate 3:

- does not show NaiveProxy in the bot;
- does not render a NaiveProxy Deployment;
- does not build a NaiveProxy Caddy image;
- rejects attempts to generate a legacy NaiveProxy client config;
- reserves UDP/443 for public Hysteria2.

Legacy enum values and migration readers may remain temporarily so old database
rows can be identified and removed without corrupting state. They are not a
supported runtime contract.
