DIR=$(dirname "$0")
RS=0

while [ "x$1" != "x" ] ; do
	echo -ne "TEST $1\t\t\t"

	"$DIR/../util/telnet-test" "$1" > "$1.run.tmp"
	sed -n '/%%/,$p' < "$1" | tail -n+2 > "$1.out.tmp"
	if cmp -s "$1.out.tmp" "$1.run.tmp" ; then
		echo "OK"
	else
		echo "FAIL"
		echo "EXPECTED:"
		sed 's/^/\t/' < "$1.out.tmp"
		echo "GOT:"
		sed 's/^/\t/' < "$1.run.tmp"
		RS=1
	fi
	rm -f "$1.run.tmp" "$1.out.tmp"

	shift
done

exit $RS
