#!/bin/bash
set -e

ROOT_DIR="./root"

sudo chown -R 0:0 "$ROOT_DIR"

sudo mkdir -p "$ROOT_DIR/etc/apt/apt.conf.d"
echo 'APT::Sandbox::User "root";' | sudo tee "$ROOT_DIR/etc/apt/apt.conf.d/99sandbox"

echo "unsafe-perm=true" | sudo tee -a "$ROOT_DIR/etc/npmrc"

sudo mkdir -p "$ROOT_DIR/etc"
echo -e "[global]\nbreak-system-packages = true" | sudo tee "$ROOT_DIR/etc/pip.conf"
