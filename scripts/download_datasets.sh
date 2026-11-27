#!/usr/bin/env bash
# Download the three public benchmark datasets used in the HybridGuard paper.
# All are free and public. Total size is a few hundred MB at most; the
# Solidity sources themselves are tiny (5-50 KB per file).
set -euo pipefail

DATA_DIR="${1:-datasets}"
mkdir -p "$DATA_DIR"
cd "$DATA_DIR"

if [ ! -d smartbugs-curated ]; then
    echo "[*] SmartBugs Curated (143 verified vulnerable contracts)..."
    git clone --depth 1 https://github.com/smartbugs/smartbugs-curated.git
fi

if [ ! -d DeFiHackLabs ]; then
    echo "[*] DeFiHackLabs (real-world DeFi exploits with Foundry PoCs)..."
    git clone --depth 1 https://github.com/SunWeb3Sec/DeFiHackLabs.git
fi

if [ ! -d openzeppelin-contracts ]; then
    echo "[*] OpenZeppelin (clean/safe contracts for the false-positive test)..."
    git clone --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git
fi

echo
echo "Done. Usage:"
echo "  hybridguard benchmark smartbugs-curated  --source smartbugs"
echo "  hybridguard benchmark DeFiHackLabs       --source defihacklabs --limit 100"
echo "  hybridguard benchmark openzeppelin-contracts/contracts --source clean"
