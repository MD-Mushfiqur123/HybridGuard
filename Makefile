.PHONY: test smoke datasets lint clean

test:
	python -m pytest tests/ -v

smoke:
	python -m hybridguard.cli scan tests/contracts/ReentrancyVault.sol --provider mock --verification none

smoke-baseline:
	python -m hybridguard.cli scan tests/contracts/ReentrancyVault.sol --provider mock --verification none --no-slicing

datasets:
	bash scripts/download_datasets.sh

clean:
	rm -rf .hybridguard __pycache__ hybridguard/__pycache__ hybridguard/*/__pycache__ .pytest_cache
