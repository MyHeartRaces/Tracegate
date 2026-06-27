# Tracegate Runtime Bundles

These are public, generic bundle templates for Tracegate 3. They contain only
placeholders, loopback listeners and documentation-reserved values. They are
not deployable production configuration until the private operator renderer
materializes external credentials, domains and role-specific settings.

`base-entry` maps to the canonical Entry role. `base-transit` is retained as a
wire-compatibility identifier for older agents but maps to the canonical
Endpoint role; it is not a third production node.

The versioned bundle manifest is part of every public release archive. Client
exports, decoy content, production values and rendered runtime state are never
included.
