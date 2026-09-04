#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="$ROOT_DIR/Vendor"
FRAMEWORK_DIR="$ROOT_DIR/Frameworks"
OLCRTC_DIR="$VENDOR_DIR/olcrtc"
OLCRTC_REF="${OLCRTC_REF:-master}"

mkdir -p "$VENDOR_DIR" "$FRAMEWORK_DIR"

if [[ ! -d "$OLCRTC_DIR/.git" ]]; then
  git clone --branch "$OLCRTC_REF" https://github.com/openlibrecommunity/olcrtc "$OLCRTC_DIR" --recurse-submodules
else
  git -C "$OLCRTC_DIR" fetch origin "$OLCRTC_REF"
  git -C "$OLCRTC_DIR" checkout "$OLCRTC_REF"
  git -C "$OLCRTC_DIR" pull --ff-only origin "$OLCRTC_REF"
  git -C "$OLCRTC_DIR" reset --hard "origin/$OLCRTC_REF"
  git -C "$OLCRTC_DIR" submodule update --init --recursive
fi

pushd "$OLCRTC_DIR" >/dev/null
echo "Using olcRTC $(git rev-parse --short HEAD) from $OLCRTC_REF"
echo "Patches skipped — master already contains all required features"
gomobile bind -target=ios -o "$FRAMEWORK_DIR/Mobile.xcframework" ./mobile
popd >/dev/null

echo "Built $FRAMEWORK_DIR/Mobile.xcframework"
