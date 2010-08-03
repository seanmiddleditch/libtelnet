DIR=$(dirname "$0")
RS=0

while [ "x$1" != "x" ] ; do
	echo -ne "TEST $1\t\t\t"

	"$DIR/../util/telnet-test" "$1" > "$1.run.tmp"
	sed -n '/%%/,$p' < "$1" | tail -n+2 > "$1.out.tmp"
	if diff -u "$1.out.tmp" "$1.run.tmp" > "$1.diff.tmp" ; then
		echo "OK"
	else
		echo "FAIL"
		cat "$1.diff.tmp"
		RS=1
	fi
	rm -f "$1.run.tmp" "$1.out.tmp" "$1.diff.tmp"

	shift
done

exit $RS
