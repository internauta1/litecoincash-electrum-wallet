#!/usr/bin/env bash
set -euo pipefail

# LCC_BETA2_MINOTAURX_WINDOWS_V1
# Build against the exact public Litecoin Cash Core commit.

: "${PROJECT_ROOT:?}"
: "${CACHEDIR:?}"
: "${DLL_TARGET_DIR:?}"
: "${GCC_TRIPLET_HOST:?}"

CORE_URL="https://github.com/internauta1/litecoincash.git"
CORE_COMMIT="ac73f25a25302039eb62e28a9bb5f5665ea9ee61"

CORE_DIR="$CACHEDIR/lcc-minotaurx-core"
BUILD_DIR="$CACHEDIR/lcc-minotaurx-windows-build"
TARGET="$DLL_TARGET_DIR/lcc_minotaurx.dll"
STAMP="$DLL_TARGET_DIR/lcc_minotaurx.commit"

mkdir -p "$DLL_TARGET_DIR"

if [[ -f "$TARGET" && -f "$STAMP" ]] &&
   [[ "$(cat "$STAMP")" == "$CORE_COMMIT" ]]; then
    echo "LCC MinotaurX: cached pinned DLL found"
    exit 0
fi

echo "===== LCC MINOTAURX WINDOWS ====="
echo "Core commit: $CORE_COMMIT"

if [[ ! -d "$CORE_DIR/.git" ]]; then
    mkdir -p "$CORE_DIR"
    git -C "$CORE_DIR" init
    git -C "$CORE_DIR" remote add origin "$CORE_URL"
fi

git -C "$CORE_DIR" fetch --depth 1 origin "$CORE_COMMIT"
git -C "$CORE_DIR" checkout --force --detach FETCH_HEAD

ACTUAL_COMMIT="$(git -C "$CORE_DIR" rev-parse HEAD)"

if [[ "$ACTUAL_COMMIT" != "$CORE_COMMIT" ]]; then
    echo "ERROR: Litecoin Cash Core commit mismatch"
    exit 1
fi

cmake \
    -S "$PROJECT_ROOT/native/minotaurx" \
    -B "$BUILD_DIR" \
    -G "Unix Makefiles" \
    -DCMAKE_SYSTEM_NAME=Windows \
    -DCMAKE_C_COMPILER="${GCC_TRIPLET_HOST}-gcc" \
    -DCMAKE_CXX_COMPILER="${GCC_TRIPLET_HOST}-g++" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_SHARED_LINKER_FLAGS="-Wl,--export-all-symbols" \
    -DLCC_CORE_SOURCE="$CORE_DIR/src"

cmake --build "$BUILD_DIR" --parallel 2

mapfile -t DLL_FILES < <(
    find "$BUILD_DIR" -maxdepth 3 -type f \
        \( -name "lcc_minotaurx.dll" \
        -o -name "liblcc_minotaurx.dll" \) \
        -print
)

if [[ "${#DLL_FILES[@]}" -ne 1 ]]; then
    echo "ERROR: Expected exactly one MinotaurX DLL"
    exit 1
fi

OBJDUMP="${GCC_TRIPLET_HOST}-objdump"

"$OBJDUMP" -p "${DLL_FILES[0]}" > "$BUILD_DIR/dll-exports.txt"

for symbol in lcc_minotaurx_hash lcc_minotaur_hash; do
    if ! grep -q "$symbol" "$BUILD_DIR/dll-exports.txt"; then
        echo "ERROR: Missing DLL symbol: $symbol"
        exit 1
    fi
done

cp "${DLL_FILES[0]}" "$TARGET"
printf '%s\n' "$CORE_COMMIT" > "$STAMP"

echo "===== RESULT ====="
echo "DLL: $TARGET"
echo "CORE COMMIT: VERIFIED"
echo "REQUIRED SYMBOLS: PRESENT"
