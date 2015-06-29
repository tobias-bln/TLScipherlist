#!/bin/sh

. $(dirname $0)/functions.sh

TMP="/tmp/ciphercheck.tmp"

VERBOSE="no"

script=$0
basename="$(dirname $script)"

#PRIMES="$basename/primes.txt"
PRIMES="/Users/tobias/Pydio/My Files/dhscan/primes.txt"

case `uname` in
	Linux)	OPENSSLPATH="/usr/bin/openssl"
		alias echo='echo -e'
		echo Linux
		;;
	Darwin)	if [ -f /usr/local/opt/openssl/bin/openssl ] ; then
			OPENSSLPATH="/usr/local/opt/openssl/bin/openssl"
		else
			OPENSSLPATH="/usr/bin/openssl"
		fi
	        echo Darwin
		;;
	*) OPENSSLPATH="openssl" ;;
esac

while getopts s:p:b:v opt
do
	case $opt in
		s) SERVER=$OPTARG;;
		p) PORT=$OPTARG;;
		b) if [ -f $OPTARG ] ; then
			SSLbin=$OPTARG
		   else
			echo ERROR: $OPTARG existiert nicht!
			exit 1
		   fi;;
		v) VERBOSE="yes";;
	esac
done

if [[ $SERVER = "" ]] || [[ $PORT = "" ]] ; then
	echo "$0 -s <SERVER> -p <PORT> [-b OPENSSLBINARY]"
	exit 1
fi

TEST_PROTO="ssl2 ssl3 tls1 tls1_1 tls1_2"
OPTIONS="-connect"
OPENSSLversion=`$OPENSSLPATH version`

echo "############################################\n# \
SSL-Test: $SERVER:$PORT\n# \
OpenSSL Version: $OPENSSLversion \n############################################\n"

case "$PORT" in
	587)	OPTIONS="-starttls smtp -connect" ;;
	443)	OPTIONS="-connect" ;;
	143)	OPTIONS="-starttls imap -connect" ;;
	25)	OPTIONS="-starttls smtp -connect" ;;
	*)	echo unknown Port: $PORT
		exit 1 ;;
esac

# todo: openssl version check
#print_keyparams

if [ "$PORT" = "443" ] ; then

    get_httpheaders

fi

exit 0

cipher_scan

get_dhparams
print_dhparams
get_servername
scan_dhprimesfile

