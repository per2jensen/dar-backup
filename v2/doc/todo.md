# TODO

## Testing

- **Low-resource test VM**: set up a Multipass VM (2 CPU, 4 GB RAM) to mirror CI conditions locally. The CI runner's tighter memory budget surfaces resource-sensitive bugs (e.g. stale log-file handles, filesystem cleanup timing) that a 64 GB workstation never triggers.
