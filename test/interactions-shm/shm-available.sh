#!/bin/sh

status=$(grep -s global-shmem /proc/*/comm | wc -l)
echo "host available: $status"
[ "${status}" = "${1}" ]
exit $?
