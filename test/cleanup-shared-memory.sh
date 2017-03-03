if [ `uname` = Darwin ]; then
	for n in `ipcs -m -c | grep $USER | egrep ^m | awk '{ print $2; }'`; do ipcrm -m $n; done
else
	for n in `ipcs -m -c | grep $USER | awk '{ print $1; }'`; do ipcrm -m $n; done
fi
