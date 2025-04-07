#!/bin/bash
set -e

tests=("fuzzNanoTDF", "fuzzTDF", "fuzzZipRead")
base_seed_dir="src/test/resources/io/opentdf/platform/sdk/FuzzingInputs/"

for test in "${tests[@]}"; do
    seed_dir="${base_seed_dir}${test}"
    echo "Running $test fuzzing with seeds from $seed_dir"
    mvn verify -P fuzz -Djazzer.testDir=$seed_dir
done
