#!/bin/sh
# Установщик netpult: качает готовый бинарь из релизов и кладёт в PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/pepetutu1337/netpult/main/install.sh | sh
#
# Если сам этот файл не скачивается — то же через зеркало:
#   curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/pepetutu1337/netpult/main/install.sh | sh
#
# Переменные:
#   NETPULT_VERSION=v0.1.0   поставить конкретную версию (по умолчанию последнюю)
#   NETPULT_BIN_DIR=~/bin    куда класть (по умолчанию ~/.local/bin)
#   NETPULT_MIRROR=https://...  свой префикс-зеркало для GitHub
#   NETPULT_NO_CORE=1        не качать ядро sing-box
#   NETPULT_ASSET=./netpult-macos-universal.tar.gz   поставить из готового файла
#   NETPULT_CORE=./sing-box                          ядро тоже из файла
#
# Последние два — для машины, которой GitHub не отдаёт вообще. Файлы качаются
# на любой рабочей машине (или берутся с флешки) и подкладываются сюда.
set -eu

REPO="pepetutu1337/netpult"
# Ядро выпускается отдельно от пульта: оно большое и меняется редко.
CORE_TAG="core-1.13.19"
BIN_DIR="${NETPULT_BIN_DIR:-$HOME/.local/bin}"

red() { printf '\033[31m%s\033[0m\n' "$1" >&2; }
say() { printf '%s\n' "$1"; }
die() { red "$1"; exit 1; }

# GitHub из России часто недоступен, а netpult — как раз утилита для тех, у кого
# он недоступен. Поэтому каждая ссылка пробуется сначала напрямую, потом через
# зеркала. Пустой префикс = прямая попытка.
fetch() { # fetch <url> <выходной файл|-> ; перебирает зеркала
  _url="$1"; _out="$2"
  # --speed-time: соединение, которое установилось и встало, обрывается через
  # двадцать секунд молчания. Без этого первая же мёртвая попытка съедала весь
  # запас времени, и до зеркал очередь не доходила.
  # ghproxy.net из списка убран: отдаёт сертификат на чужое имя, curl рвёт
  # соединение (ошибка 60) и восемь секунд ожидания уходят впустую.
  for _m in ${NETPULT_MIRROR:-} "" https://gh-proxy.com/ https://ghfast.top/; do
    if [ "$_out" = "-" ]; then
      curl -fsL --connect-timeout 8 --max-time 30 --speed-time 15 --speed-limit 512 \
        "$_m$_url" && return 0
    else
      curl -fsL --connect-timeout 8 --max-time 180 --speed-time 20 --speed-limit 1024 \
        -o "$_out" "$_m$_url" && return 0
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

# Готовый файл под рукой — качать нечего.
if [ -n "${NETPULT_ASSET:-}" ]; then
  [ -f "$NETPULT_ASSET" ] || die "нет файла $NETPULT_ASSET"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  tar xzf "$NETPULT_ASSET" -C "$tmp" || die "$NETPULT_ASSET — не тот архив"
  mkdir -p "$BIN_DIR"
  install -m755 "$tmp/netpult" "$BIN_DIR/netpult" 2>/dev/null \
    || { cp "$tmp/netpult" "$BIN_DIR/netpult" && chmod 755 "$BIN_DIR/netpult"; }
  [ "$os" = macos ] && xattr -d com.apple.quarantine "$BIN_DIR/netpult" 2>/dev/null || true
  say "Готово: $BIN_DIR/netpult"
  case "$os" in
    macos) state_dir="$HOME/Library/Application Support/netpult" ;;
    *)     state_dir="${XDG_DATA_HOME:-$HOME/.local/share}/netpult" ;;
  esac
  if [ -n "${NETPULT_CORE:-}" ]; then
    [ -f "$NETPULT_CORE" ] || die "нет файла $NETPULT_CORE"
    mkdir -p "$state_dir"
    install -m755 "$NETPULT_CORE" "$state_dir/sing-box" 2>/dev/null \
      || { cp "$NETPULT_CORE" "$state_dir/sing-box" && chmod 755 "$state_dir/sing-box"; }
    [ "$os" = macos ] && xattr -d com.apple.quarantine "$state_dir/sing-box" 2>/dev/null || true
    say "Ядро: $state_dir/sing-box"
  else
    say "Ядро не подложено — поставить потом: netpult vpn core install"
  fi
  case ":$PATH:" in
    *":$BIN_DIR:"*) "$BIN_DIR/netpult" version || true ;;
    *) say ""; say "$BIN_DIR не в PATH. Добавь в ~/.bashrc или ~/.zshrc:"
       say "  export PATH=\"$BIN_DIR:\$PATH\"" ;;
  esac
  exit 0
fi

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
if ! fetch "$url" "$tmp/$asset"; then
  red "не скачалось: $url"
  red ""
  red "Файлы релизов GitHub лежат на release-assets.githubusercontent.com, и"
  red "в России этот адрес часто режут до нескольких сотен байт в секунду."
  red "Что помогает:"
  red "  · включить обход или VPN и повторить;"
  red "  · своё зеркало: NETPULT_MIRROR=https://ваше-зеркало/ sh install.sh"
  red "  · собрать из исходников: cargo build --release"
  exit 1
fi

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

# Ядро sing-box — половина пульта: без него нет ни туннеля, ни выбора ноды.
# Качаем сразу, чтобы «поставил и работает» было правдой. Отказаться:
# NETPULT_NO_CORE=1.
if [ -z "${NETPULT_NO_CORE:-}" ]; then
  case "$os" in
    linux) core_asset="sing-box-linux-x86_64" ;;
    macos) core_asset="sing-box-macos-universal" ;;
  esac
  case "$os" in
    macos) state_dir="$HOME/Library/Application Support/netpult" ;;
    *)     state_dir="${XDG_DATA_HOME:-$HOME/.local/share}/netpult" ;;
  esac
  mkdir -p "$state_dir"
  say ""
  say "Качаю ядро sing-box (~55 МБ, один раз)..."
  if fetch "https://github.com/$REPO/releases/download/$CORE_TAG/$core_asset" "$tmp/core"; then
    install -m755 "$tmp/core" "$state_dir/sing-box" 2>/dev/null \
      || { cp "$tmp/core" "$state_dir/sing-box" && chmod 755 "$state_dir/sing-box"; }
    [ "$os" = macos ] && xattr -d com.apple.quarantine "$state_dir/sing-box" 2>/dev/null || true
    say "Ядро: $state_dir/sing-box"
  else
    red "ядро не скачалось — поставить потом: netpult vpn core install"
  fi
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) "$BIN_DIR/netpult" version || true ;;
  *)
    say ""
    say "$BIN_DIR не в PATH. Добавь в ~/.bashrc или ~/.zshrc:"
    say "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac
