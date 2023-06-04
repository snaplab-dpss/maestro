#!/bin/bash

. /home/user/maestro/build/paths.sh

if [[ ! -z "${HUGE}" ]]; then
	sudo -E /home/user/allocate-hugepages.sh
fi

sudo -E /home/user/bind-igb-uio.sh "$DEV0" "$DEV1"
exec "$@"