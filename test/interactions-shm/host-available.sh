#!/bin/sh

status=$(pidof -q test-host && echo yes || echo no)
echo "host available: $status"
[ "${status}" = "${1}" ]
exit $?
