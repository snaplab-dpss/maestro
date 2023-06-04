# Running an NF in a docker container

```
$ docker run \
	--rm \
	--privileged \
	-v /mnt:/mnt \
	-v /lib/firmware:/lib/firmware/ \
	-v /sys/devices/system:/sys/devices/system \
	-v /dev:/dev \
	--env DEV0={{PCIE DEVICE ID}} \
	--env DEV1={{PCIE DEVICE ID}} \
	--env HUGE=1 \
	-it \
	maestro \
	sudo {{NF}}
```

For example, running the shared nothing `nop` in our setup:

```
$ docker run \
	--rm \
	--privileged \
	-v /mnt:/mnt \
	-v /lib/firmware:/lib/firmware/ \
	-v /sys/devices/system:/sys/devices/system \
	-v /dev:/dev \
	--env DEV0=0000:d8:00.0 \
	--env DEV1=0000:d8:00.1 \
	--env HUGE=1 \
	-it \
	maestro \
	sudo build/apps/nop-sn
```