#!/usr/bin/env bash
# reproduce_all.sh
#
# Reproduces the full thesis evaluation (Chapter 8) in one command.
# Clones each evaluated library at the exact version used in the thesis,
# applies the TRUST_BOUNDARY annotations, builds the checker, runs CodeChecker,
# and prints the metrics from Tables 8.2 and 8.3.
#
# Prerequisites: clang, llvm, cmake, ninja, python3, codechecker, git
# Estimated runtime: 10–20 minutes depending on machine and network speed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"
WORK_DIR="$REPO_ROOT/_reproduce"
RESULTS_DIR="$REPO_ROOT/_results"
LOG_DIR="$REPO_ROOT/_logs"
ANNOTATED="$REPO_ROOT/evaluated_libraries"

mkdir -p "$WORK_DIR" "$RESULTS_DIR" "$LOG_DIR"

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Step 1: Build the plugin ─────────────────────────────────────────────────
info "Building checker plugin..."
bash "$REPO_ROOT/scripts/build.sh" || error "Build failed. Check prerequisites."
PLUGIN="$BUILD_DIR/SecurityMiscPlugin.so"
[ -f "$PLUGIN" ] || error "Plugin not found at $PLUGIN after build."
info "Plugin built: $PLUGIN"

# ── Step 2: Run synthetic benchmarks ─────────────────────────────────────────
info "Running synthetic benchmark suite (Appendix A)..."
bash "$REPO_ROOT/scripts/run_synthetic.sh" \
  || warn "Synthetic suite: some cases did not match expected output (see known limitations)."

# ── Step 3: Clone and annotate libraries ─────────────────────────────────────
clone_and_annotate() {
  local name="$1" url="$2" tag="$3" annotated_src="$4"
  local dest="$WORK_DIR/$name"

  if [ -d "$dest/.git" ]; then
    info "$name: already cloned, skipping."
  else
    info "$name: cloning $url @ $tag ..."
    git clone --quiet --depth 1 --branch "$tag" "$url" "$dest"
  fi

  if [ -d "$annotated_src" ]; then
    info "$name: applying TRUST_BOUNDARY annotations..."
    cp -r "$annotated_src/." "$dest/"
  fi
}

clone_and_annotate "zlib"       "https://github.com/madler/zlib"          "v1.3.1"  "$ANNOTATED/zlib"
clone_and_annotate "libuv"      "https://github.com/libuv/libuv"          "v1.48.0" "$ANNOTATED/libuv"
clone_and_annotate "raylib"     "https://github.com/raysan5/raylib"       "5.0"     "$ANNOTATED/raylib"
clone_and_annotate "chipmunk2d" "https://github.com/slembcke/Chipmunk2D"  "Chipmunk-7.0.3" "$ANNOTATED/chipmunk2d"

# ── Step 4: Build each library and generate compile_commands.json ─────────────
build_library() {
  local name="$1"; shift; local cmake_args=("$@")
  local src="$WORK_DIR/$name"
  local bld="$WORK_DIR/${name}_build"

  info "$name: configuring..."
  cmake -S "$src" -B "$bld" -G Ninja \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    "${cmake_args[@]}" \
    > "$LOG_DIR/${name}_cmake.log" 2>&1 \
    || { warn "$name: cmake failed — see $LOG_DIR/${name}_cmake.log"; return 1; }

  info "$name: building (needed for full compile_commands)..."
  ninja -C "$bld" -j"$(nproc)" \
    > "$LOG_DIR/${name}_build.log" 2>&1 \
    || { warn "$name: build had errors — compile_commands may still be usable"; }

  echo "$bld/compile_commands.json"
}

DB_ZLIB=$(build_library       "zlib"       )
DB_LIBUV=$(build_library      "libuv"      -DLIBUV_BUILD_TESTS=OFF)
DB_RAYLIB=$(build_library     "raylib"     -DBUILD_EXAMPLES=OFF)
DB_CHIPMUNK=$(build_library   "chipmunk2d" -DBUILD_DEMOS=OFF)

# ── Step 5: Run CodeChecker on each library ───────────────────────────────────
run_project() {
  local name="$1" db="$2" src="$3"
  local log="$LOG_DIR/${name}_events.csv"
  local cc_out="$RESULTS_DIR/$name"

  info "$name: running CodeChecker analysis..."
  export PADDING_LEAK_LOG="$log"
  bash "$REPO_ROOT/scripts/run_codechecker.sh" "$src" "$db" "$cc_out" \
    > "$LOG_DIR/${name}_cc.log" 2>&1 \
    || warn "$name: CodeChecker exited non-zero — results may still be present."

  echo "$log"
}

LOG_ZLIB=$(run_project       "zlib"       "$DB_ZLIB"     "$WORK_DIR/zlib")
LOG_LIBUV=$(run_project      "libuv"      "$DB_LIBUV"    "$WORK_DIR/libuv")
LOG_RAYLIB=$(run_project     "raylib"     "$DB_RAYLIB"   "$WORK_DIR/raylib")
LOG_CHIPMUNK=$(run_project   "chipmunk2d" "$DB_CHIPMUNK" "$WORK_DIR/chipmunk2d")

# ── Step 6: Collect and print metrics ────────────────────────────────────────
info "Collecting metrics (Tables 8.2 and 8.3)..."

python3 "$REPO_ROOT/scripts/collect_metrics.py" \
  --logs \
    "zlib:$LOG_ZLIB" \
    "libuv:$LOG_LIBUV" \
    "raylib:$LOG_RAYLIB" \
    "chipmunk2d:$LOG_CHIPMUNK" \
  --cc-results \
    "zlib:$RESULTS_DIR/zlib/json/results.json" \
    "libuv:$RESULTS_DIR/libuv/json/results.json" \
    "raylib:$RESULTS_DIR/raylib/json/results.json" \
    "chipmunk2d:$RESULTS_DIR/chipmunk2d/json/results.json"

info "Done. Full logs in $LOG_DIR, CodeChecker results in $RESULTS_DIR."
