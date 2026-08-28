#!/bin/sh
# Собрать ядро sing-box под три системы, включая macOS 11 Big Sur.
#
# Готовые сборки sing-box собраны компилятором Go, который ставит минимальную
# версию macOS 12 и выше — на Big Sur они падают в dyld. Минимальная версия
# определяется версией Go, а не машиной сборки, поэтому ядро для старых маков
# собирается Go 1.24: он последний, кто ставит minos 11.0.
#
#   tools/build-core.sh [версия sing-box] [каталог вывода]
set -eu

VERSION="${1:-v1.13.19}"
OUT="${2:-dist}"
# Go 1.24 — последний, кто ставит маковский minos 11.0. Он же ломает сборку под
# Windows: tfo-go лезет во внутренности net через linkname, а в 1.24 их
# перекрыли. Поэтому маки собираем старым Go, остальных — свежим.
GO_MAC="go1.24.10"
GO_NEW="go1.25.3"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

say() { printf '%s\n' "$1"; }

# Каталог вывода приводим к полному пути: собираем из чужого каталога, и
# относительный путь превратился бы в мусор.
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# Go нужных версий — рядом с исходниками, чтобы не трогать системный.
fetch_go() { # fetch_go <версия> ; печатает путь к go
  _dir="$WORK/$1"
  if [ ! -x "$_dir/bin/go" ]; then
    say "Качаю $1..." >&2
    curl -sSL -o "$WORK/$1.tar.gz" "https://dl.google.com/go/$1.linux-amd64.tar.gz"
    mkdir -p "$_dir"
    tar xzf "$WORK/$1.tar.gz" -C "$_dir" --strip-components=1
  fi
  printf '%s\n' "$_dir/bin/go"
}
GO_MAC_BIN="$(fetch_go "$GO_MAC")"
GO_NEW_BIN="$(fetch_go "$GO_NEW")"

say "Беру sing-box $VERSION..."
git clone -q --depth 1 -b "$VERSION" https://github.com/SagerNet/sing-box "$WORK/src"
TAGS="$(cat "$WORK/src/release/DEFAULT_BUILD_TAGS_OTHERS")"
build() { # build <goos> <goarch> <имя файла>
  say "  $3"
  _go="$GO_NEW_BIN"
  [ "$1" = darwin ] && _go="$GO_MAC_BIN"
  ( cd "$WORK/src" && CGO_ENABLED=0 GOOS="$1" GOARCH="$2" GOTOOLCHAIN=local \
      MACOSX_DEPLOYMENT_TARGET=11.0 "$_go" build -trimpath \
      -tags "$TAGS" -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=${VERSION#v}" \
      -o "$OUT/$3" ./cmd/sing-box )
}

build linux amd64 sing-box-linux-x86_64
build darwin amd64 sing-box-macos-x86_64
build darwin arm64 sing-box-macos-arm64
build windows amd64 sing-box-windows-x86_64.exe

# Универсальный маковский бинарь склеивает lipo, а его на Линуксе нет.
# Формат простой: заголовок с описанием кусков и сами куски по смещениям.
python3 - "$OUT/sing-box-macos-x86_64" "$OUT/sing-box-macos-arm64" "$OUT/sing-box-macos-universal" <<'ENDPY'
import struct, sys

x86_path, arm_path, out_path = sys.argv[1:4]
ALIGN = 14  # 2**14 — как выравнивает lipo
slices = [
    (0x01000007, 0x80000003, open(x86_path, "rb").read()),  # x86_64
    (0x0100000C, 0x00000000, open(arm_path, "rb").read()),  # arm64
]

offsets, position = [], 1 << ALIGN
for _, _, data in slices:
    offsets.append(position)
    position = (position + len(data) + (1 << ALIGN) - 1) & ~((1 << ALIGN) - 1)

blob = struct.pack(">II", 0xCAFEBABE, len(slices))
for (cpu, sub, data), offset in zip(slices, offsets):
    blob += struct.pack(">5I", cpu, sub, offset, len(data), ALIGN)
for (_, _, data), offset in zip(slices, offsets):
    blob += b"\0" * (offset - len(blob)) + data

open(out_path, "wb").write(blob)
print(f"  sing-box-macos-universal ({len(blob)} bytes)")
ENDPY

say "Готово: $OUT"
ls -1 "$OUT"
