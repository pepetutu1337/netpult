#!/bin/sh
# Установщик netpult: качает готовый бинарь из релизов и кладёт в PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/pepetutu1337/netpult/main/install.sh | sh
#
# Переменные:
#   NETPULT_VERSION=v0.1.0   поставить конкретную версию (по умолчанию последнюю)
#   NETPULT_BIN_DIR=~/bin    куда класть (по умолчанию ~/.local/bin)
#   NETPULT_MIRROR=https://...  свой префикс-зеркало для GitHub
set -eu

REPO="pepetutu1337/netpult"
BIN_DIR="${NETPULT_BIN_DIR:-$HOME/.local/bin}"

red() { printf '\033[31m%s\033[0m\n' "$1" >&2; }
say() { printf '%s\n' "$1"; }
die() { red "$1"; exit 1; }

# GitHub из России часто недоступен, а netpult — как раз утилита для тех, у кого
# он недоступен. Поэтому каждая ссылка пробуется сначала напрямую, потом через
# зеркала. Пустой префикс = прямая попытка.
fetch() { # fetch <url> <выходной файл|-> ; перебирает зеркала
  _url="$1"; _out="$2"
  for _m in ${NETPULT_MIRROR:-} "" https://ghproxy.net/ https://gh-proxy.com/ https://ghfast.top/; do
    if [ "$_out" = "-" ]; then
      curl -fsL --connect-timeout 10 --max-time 60 "$_m$_url" && return 0
    else
      curl -fsL --connect-timeout 10 --max-time 300 -o "$_out" "$_m$_url" && return 0
    fi
  done
  return 1
}

command -v curl >/dev/null || die "нужен curl"
command -v tar  >/dev/null || die "нужен tar"

case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=macos ;;
  *) die "эта система ставится не так: Windows — install.ps1, остальное — сборкой из исходников" ;;
esac

arch="$(uname -m)"
case "$os:$arch" in
  linux:x86_64|linux:amd64) asset="netpult-linux-x86_64.tar.gz" ;;
  macos:arm64|macos:x86_64) asset="netpult-macos-universal.tar.gz" ;;
  linux:aarch64|linux:arm64)
    die "готового бинаря под Linux ARM нет. Собери из исходников: cargo build --release" ;;
  *) die "неизвестная связка $os/$arch" ;;
esac

version="${NETPULT_VERSION:-}"
if [ -z "$version" ]; then
  say "Ищу последний релиз..."
  version="$(fetch "https://api.github.com/repos/$REPO/releases/latest" - \
    | sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' | head -n1)" || true
  [ -n "$version" ] || die "не достучаться до GitHub. Укажи версию руками: NETPULT_VERSION=v0.1.0, или задай своё зеркало через NETPULT_MIRROR"
fi

url="https://github.com/$REPO/releases/download/$version/$asset"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "Качаю netpult $version ($os/$arch)..."
fetch "$url" "$tmp/$asset" || die "не скачалось: $url"

if fetch "$url.sha256" "$tmp/$asset.sha256" 2>/dev/null; then
  expected="$(awk '{print $1}' "$tmp/$asset.sha256")"
  if command -v sha256sum >/dev/null; then actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
  else actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"; fi
  [ "$expected" = "$actual" ] || die "контрольная сумма не сошлась — файл битый или подменён"
  say "Контрольная сумма сошлась."
fi

tar xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$BIN_DIR"
install -m755 "$tmp/netpult" "$BIN_DIR/netpult" 2>/dev/null \
  || { cp "$tmp/netpult" "$BIN_DIR/netpult" && chmod 755 "$BIN_DIR/netpult"; }

# Скачанное браузером или curl macOS помечает карантином и отказывается
# запускать. Метка снимается прямо здесь, руками потом не надо.
[ "$os" = macos ] && xattr -d com.apple.quarantine "$BIN_DIR/netpult" 2>/dev/null || true

say "Готово: $BIN_DIR/netpult"

case ":$PATH:" in
  *":$BIN_DIR:"*) "$BIN_DIR/netpult" version || true ;;
  *)
    say ""
    say "$BIN_DIR не в PATH. Добавь в ~/.bashrc или ~/.zshrc:"
    say "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac
