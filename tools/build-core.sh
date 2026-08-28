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
GO_VERSION="go1.24.10"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

say() { printf '%s\n' "$1"; }

# Go нужной версии — рядом с исходниками, чтобы не трогать системный.
if [ -x "$WORK/$GO_VERSION/bin/go" ]; then
  GO="$WORK/$GO_VERSION/bin/go"
else
  say "Качаю $GO_VERSION..."
  curl -sSL -o "$WORK/go.tar.gz" "https://dl.google.com/go/$GO_VERSION.linux-amd64.tar.gz"
  mkdir -p "$WORK/go"
  tar xzf "$WORK/go.tar.gz" -C "$WORK/go" --strip-components=1
  GO="$WORK/go/bin/go"
fi

say "Беру sing-box $VERSION..."
git clone -q --depth 1 -b "$VERSION" https://github.com/SagerNet/sing-box "$WORK/src"
TAGS="$(cat "$WORK/src/release/DEFAULT_BUILD_TAGS_OTHERS")"
mkdir -p "$OUT"

build() { # build <goos> <goarch> <имя файла>
  say "  $3"
  ( cd "$WORK/src" && CGO_ENABLED=0 GOOS="$1" GOARCH="$2" GOTOOLCHAIN=local \
      MACOSX_DEPLOYMENT_TARGET=11.0 "$GO" build -trimpath \
      -tags "$TAGS" -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=${VERSION#v}" \
      -o "$OLDPWD/$OUT/$3" ./cmd/sing-box )
}

build linux amd64 sing-box-linux-x86_64
build darwin amd64 sing-box-macos-x86_64
build darwin arm64 sing-box-macos-arm64
build windows amd64 sing-box-windows-x86_64.exe

# Универсальный маковский бинарь склеивается lipo, а его на Линуксе нет —
# заголовок Mach-O тривиальный, склеиваем сами.
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
