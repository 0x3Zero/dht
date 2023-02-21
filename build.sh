#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail

# set current working directory to script directory to run script from everywhere
cd "$(dirname "$0")"

# This script builds all subprojects and puts all created Wasm modules in one dir
cargo update --aggressive
marine build --release

mkdir -p artifacts
rm -f artifacts/*.wasm
cp target/wasm32-wasi/release/dht.wasm artifacts/
marine aqua artifacts/dht.wasm -s dht -i dht > ./aqua/dht.aqua

wget https://github.com/fluencelabs/sqlite/releases/download/v0.15.0_w/sqlite3.wasm
mv sqlite3.wasm artifacts/

cp -f artifacts/*.wasm builtins/

RUST_LOG="info" mrepl --quiet Config.toml