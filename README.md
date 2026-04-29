# clang-padding-leakage-checker

A Clang-Tidy plugin that detects **padding-byte information leakage** at
explicitly annotated trust boundaries in C/C++. The checker uses AST-level
record layout metadata to identify by-value aggregate transfers that expose
compiler-introduced padding bytes which may be uninitialized.

This is the research prototype accompanying the MSc thesis:

> **Detecting and Explaining Cryptographic Misuse in C/C++ via LLVM/Clang:
> A Taxonomy-Driven Integration into CodeChecker**  
> Chandler Camarena — Eötvös Loránd University, Faculty of Informatics (2026)  
> Supervisor: Zoltán Porkoláb

The thesis PDF is included in this repository as `Camarena_Thesis.pdf`.

---

## Quick Start

```bash
# 1. Build the plugin
bash scripts/build.sh

# 2. Run the synthetic benchmark suite (Appendix A)
bash scripts/run_synthetic.sh

# 3. Reproduce the full thesis evaluation (requires cloning evaluated libraries)
bash scripts/reproduce_all.sh
```

See [Building](#building) and [Reproducing the Thesis Evaluation](#reproducing-the-thesis-evaluation) below for prerequisites and details.

---

## Repository Structure

```
clang-padding-leakage-checker/
├── include/
│   └── trust_boundary.h              # TRUST_BOUNDARY annotation macro
├── src/
│   ├── CMakeLists.txt
│   ├── checks/
│   │   ├── TrustBoundaryPaddingLeakCheck.h
│   │   └── TrustBoundaryPaddingLeakCheck.cpp   # core checker implementation
│   └── module/
│       └── SecurityMiscModule.cpp               # plugin entry point
├── synthetic_benchmarks/
│   └── benchmarks.c                  # all 8 validation cases (Appendix A)
├── evaluated_libraries/              # annotated versions of the 4 evaluated projects
│   ├── README.md                     # what was annotated and why
│   ├── zlib/                         # annotated source files only
│   ├── libuv/
│   ├── raylib/
│   └── chipmunk2d/
├── scripts/
│   ├── build.sh                      # build the plugin
│   ├── run_synthetic.sh              # run and validate synthetic benchmarks
│   ├── run_codechecker.sh            # run CodeChecker on a single project
│   ├── collect_metrics.py            # parse event log → thesis Tables 8.2–8.3
│   └── reproduce_all.sh             # clone libraries, apply annotations, run all
├── .clang-tidy
├── .gitignore
├── codechecker.json
├── LICENSE
├── Camarena_Thesis.pdf
└── README.md
```

---

## Implemented Check

| Check name | Taxonomy ref | What it detects |
|---|---|---|
| `security-misc-padding-boundary-leak` | §5.5 / Ch. 6–7 | Record objects transferred by value across `TRUST_BOUNDARY`-annotated functions when the ABI layout contains padding bytes that may be uninitialized |

The checker assigns one of two evidence levels (thesis §5.6):

| Level | Meaning |
|---|---|
| `E3` | Padding present + field-wise-only initialization visible at call site (high confidence) |
| `E2` | Padding present + initialization state not visible under translation-unit scope (bounded confidence) |

---

## Building

### Prerequisites

**Arch Linux**
```bash
sudo pacman -S clang llvm cmake ninja python
```

**Ubuntu 24.04**
```bash
sudo apt install clang-18 llvm-18-dev clang-tidy-18 cmake ninja-build python3
```

The LLVM version used to build the plugin and the `clang-tidy` binary that
loads it **must match**. Verify before building:

```bash
clang --version
llvm-config --version
```

The thesis evaluation was run on LLVM/Clang 21.1.8 and CodeChecker 6.27.3.

### Compile

```bash
bash scripts/build.sh
```

Output: `build/SecurityMiscPlugin.so`

### Verify the plugin loads

```bash
clang-tidy -load build/SecurityMiscPlugin.so \
  -checks='*' -list-checks 2>/dev/null | grep security-misc
```

Expected output:
```
security-misc-padding-boundary-leak
```

---

## Running the Checker

### On the evaluated libraries (pre-annotated, recommended starting point)

The four libraries from the thesis evaluation are included in
`evaluated_libraries/` with `TRUST_BOUNDARY` annotations already applied.
`reproduce_all.sh` clones each library, copies the annotated files in, and
runs everything automatically — no manual annotation needed.

```bash
bash scripts/reproduce_all.sh
```

See [Reproducing the Thesis Evaluation](#reproducing-the-thesis-evaluation)
for details on what each project demonstrates.

### On a single file

```bash
clang-tidy \
  -load build/SecurityMiscPlugin.so \
  -checks='-*,security-misc-padding-boundary-leak' \
  your_file.c -- -I./include
```

### Via CodeChecker on a project with a compilation database

Install CodeChecker:
```bash
pip install codechecker
```

Run the evaluation pipeline:
```bash
export PADDING_LEAK_LOG=./events.csv
bash scripts/run_codechecker.sh /path/to/project /path/to/compile_commands.json
```

---

## Annotating Your Own Project

To run the checker on a project not included here, you need to mark which
functions represent trust-boundary crossings. The checker will only flag
by-value record transfers at functions you explicitly annotate — it does not
infer boundaries automatically (see [Known Limitations](#known-limitations)).

**Step 1 — Include the annotation header**

Copy `include/trust_boundary.h` into your project or add `include/` to your
compiler's include path.

**Step 2 — Annotate boundary functions**

Add `TRUST_BOUNDARY` to any function declaration whose by-value record
arguments or return values cross a trust domain:

```c
#include "trust_boundary.h"

/* Annotate the declaration, not just the definition */
TRUST_BOUNDARY int send_packet(struct Packet pkt);
TRUST_BOUNDARY struct Reply receive_reply(void);
```

`TRUST_BOUNDARY` expands to `__attribute__((annotate("trust_boundary")))` under
Clang/GCC and is silently ignored by other compilers and tools.

A function is a good candidate for annotation if it:
- is externally visible on a public API surface,
- accepts or returns a struct or class object by value, and
- represents a conceptual transition between components with different
  confidentiality assumptions (e.g., library-internal state to external caller,
  trusted enclave to untrusted host, kernel to userspace).

**Step 3 — Generate a compilation database and run**

```bash
# CMake projects
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ...

# Then run the checker
export PADDING_LEAK_LOG=./events.csv
bash scripts/run_codechecker.sh /path/to/project compile_commands.json
```

---

## Synthetic Benchmark Suite (Appendix A)

`synthetic_benchmarks/benchmarks.c` contains all 8 validation cases from
Appendix A. Run and validate in one step:

```bash
bash scripts/run_synthetic.sh
```

Expected results:

| Case | Scenario | Expected |
|---|---|---|
| `case01` | Padding present, uninit pass-by-value | **WARN** |
| `case02` | Padding present, `memset` zero | no warn† |
| `case03` | No padding in type | no warn |
| `case04` | Padding present, uninit return-by-value | **WARN** |
| `case05` | `__attribute__((packed))`, no padding | no warn |
| `case06` | Field-wise init only | **WARN** |
| `case07` | `= {0}` whole-object init | no warn |
| `case08` | Nested struct with padding | **WARN** |

† case02 currently produces a false positive — `memset`-based suppression is
not yet implemented (see [Known Limitations](#known-limitations)).

---

## Reproducing the Thesis Evaluation

`scripts/reproduce_all.sh` clones each evaluated library at the exact
commit used in the thesis, copies the annotated boundary files from
`evaluated_libraries/`, builds the checker, runs CodeChecker on each project,
and collects the metrics reported in Tables 8.2 and 8.3.

```bash
bash scripts/reproduce_all.sh
```

The script will print per-project event counts, padding rates, diagnostic
counts, and overhead figures matching the thesis results.

See `evaluated_libraries/README.md` for the list of annotated functions,
exact library versions, and what the annotations represent.

---

## Diagnostic Output

A typical finding looks like:

```
cpArbiter.c:87:10: warning: [E2] boundary transfer of 'cpContactPointSet'
(56 bytes, 4 padding bytes) by value at trust boundary
'cpArbiterGetContactPointSet': the ABI copies the full object representation
including padding bytes that may contain indeterminate or stale data.
Remediation: (a) zero-initialize before assignment (e.g., `cpContactPointSet v = {0};`),
or (b) serialise only semantic fields into an explicit boundary buffer.
[security-misc-padding-boundary-leak]
```

---

## Known Limitations

Documented as future work in Chapter 9 of the thesis:

- **`memset` suppression not implemented** — whole-object initialization via
  `memset(&obj, 0, sizeof obj)` is not yet recognized as a suppression
  condition. The `= {0}` idiom is correctly handled. (§9.1)
- **No interprocedural analysis** — initialization through helper functions
  defined in separate translation units is not tracked. All real-world findings
  are therefore classified E2 rather than E3. (§9.3)
- **No pointer or alias tracking** — only by-value transfers are modeled;
  pointer-mediated transfers require alias analysis and are out of scope. (§9.4)
- **Explicit boundary annotations required** — `TRUST_BOUNDARY` must be added
  manually; automatic boundary inference is future work. (§9.2)

---

## License

MIT — see [LICENSE](LICENSE).
