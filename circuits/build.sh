#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

B=circuits/build
mkdir -p $B

circom circuits/merkle_membership.circom --r1cs --wasm --sym -l node_modules -o $B

if [ ! -f $B/pot14_final.ptau ]; then
  npx snarkjs powersoftau new bn128 14 $B/pot14_0.ptau
  npx snarkjs powersoftau contribute $B/pot14_0.ptau $B/pot14_1.ptau --name="dev" -e="$(openssl rand -hex 32)"
  npx snarkjs powersoftau prepare phase2 $B/pot14_1.ptau $B/pot14_final.ptau
fi

npx snarkjs groth16 setup $B/merkle_membership.r1cs $B/pot14_final.ptau $B/mm_0.zkey
npx snarkjs zkey contribute $B/mm_0.zkey $B/mm_final.zkey --name="dev" -e="$(openssl rand -hex 32)"
npx snarkjs zkey export verificationkey $B/mm_final.zkey $B/verification_key.json
npx snarkjs r1cs info $B/merkle_membership.r1cs
