# Running an NF in a docker container

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
	maestro \
	build/apps/{{NF}}
```