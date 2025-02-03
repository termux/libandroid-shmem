#!/bin/sh

set -e

ca=$(./test-status)
cr=$(pidof test-endless-attachment | tr ' ' '\n' | wc -l)

if [ "${ca}" = "${cr}" ]; then
	echo "check-attachments - ok"
	exit 0
fi

echo "check-attachments - no matches (ca:${ca} vs cr:${cr})"
for pid in $(pidof test-endless-attachment); do
	kill $pid
done
./test-remove &> /dev/null || true
exit 1
