#!/bin/bash

cd $(pwd)/probes/
./build.sh
cd ..
cargo build --release

