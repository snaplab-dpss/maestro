#!/bin/bash

set -euo pipefail

if [ ! -d tsx-tools ]; then
	git clone https://github.com/fchamicapereira/tsx-tools.git
fi

pushd tsx-tools >/dev/null
	make
	./has-tsx
popd >/dev/null