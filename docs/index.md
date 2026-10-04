# sneppx-shield

Skeleton documentation (WIP).

## Batch verification

`signature.verify_batch(paths)` verifies multiple detached signatures and
`signature.verify_artifact(path)` returns `(ok, detail)` for a single
artifact. For directory artifacts each file must carry its own `.sig`.
