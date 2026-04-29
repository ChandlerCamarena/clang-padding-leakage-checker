# Evaluated Libraries

This directory contains the annotated source files for the four C libraries
evaluated in Chapter 8 of the thesis. Only the files that were modified to add
`TRUST_BOUNDARY` annotations are included here — the rest of each library is
cloned from its upstream repository by `scripts/reproduce_all.sh` at the exact
commit used for the thesis evaluation.

---

## Library Versions

| Library | Version / Commit | Repository |
|---|---|---|
| zlib | v1.3.1 | https://github.com/madler/zlib |
| libuv | v1.48.0 | https://github.com/libuv/libuv |
| raylib | v5.0 | https://github.com/raysan5/raylib |
| Chipmunk2D | v7.0.3 | https://github.com/slembcke/Chipmunk2D |

---

## Annotated Boundary Functions

### zlib — `zlib/`

No by-value aggregate transfers exist at the annotated interfaces. zlib is
included as the null-case baseline (thesis §8.6.1). The annotations are present
but produce zero boundary-transfer events.

Annotated functions: `deflate`, `deflateEnd`, `inflate`, `inflateEnd`,
`deflateSetHeader`

Modified files: `zlib.h`

### libuv — `libuv/`

One by-value return exists (`uv_buf_init`). On Linux x86-64 the returned type
`uv_buf_t` contains no padding, so no diagnostic is emitted. Included to
demonstrate platform-sensitive layout computation (thesis §8.6.1).

Annotated functions: `uv_buf_init`, `uv_now`, `uv_hrtime`, `uv_get_free_memory`,
`uv_get_total_memory`

Modified files: `include/uv.h`

### raylib — `raylib/`

All five annotated functions return `RayCollision` by value. The struct has
3 bytes of ABI padding, but all return sites use `= {0}` initialization, so
all findings are correctly suppressed (thesis §8.6.1).

Annotated functions: `GetRayCollisionSphere`, `GetRayCollisionBox`,
`GetRayCollisionMesh`, `GetRayCollisionTriangle`, `GetRayCollisionQuad`

Modified files: `src/rshapes.c`, `include/raylib.h`

### Chipmunk2D — `chipmunk2d/`

The primary positive-case study. `cpContactPointSet` has a 4-byte padding gap
between `count` (int) and `normal` (cpVect, 8-byte aligned). Both annotated
functions return this struct by value using field-wise initialization with no
prior zero-initialization. The checker emits four E2 diagnostics across two
translation units (thesis §8.6.1).

Annotated functions: `cpArbiterGetContactPointSet`, `cpShapesCollide`,
`cpShapeGetBB`

Modified files: `include/chipmunk/cpArbiter.h`, `include/chipmunk/cpShape.h`

---

## Usage

`scripts/reproduce_all.sh` handles cloning and patching automatically.
To inspect what was changed manually, diff any file here against its upstream
counterpart at the version listed above. The only change in every file is the
addition of `TRUST_BOUNDARY` to specific function declarations.
