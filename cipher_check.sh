#!/bin/sh

. $(dirname $0)/dhscan.sh

TMP="/tmp/ciphercheck.tmp"
VERBOSE="no"

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

if [ -f /usr/local/opt/openssl/bin/openssl ] ; then
	echo Key Parameters:
	echo | /usr/local/opt/openssl/bin/openssl s_client $OPTIONS $SERVER:$PORT -cipher "DH" \
		2>/dev/null | grep -iE "key.*bit.*"
	echo "\n"
fi

if [ "$PORT" = "443" ] ; then

	#HSTS="no"
	#HPKP="no"
	#HTTPKeepAlive="yes"

	echo "Check for HSTS and HPKP Headers:"
	curl -sI https://$SERVER > $TMP
	while read line 
	do
		case $line in
			*Strict-Transport-Security*)	echo $line 
							HSTS="yes"
							echo $line | grep -iEo "max-age=[0-9]+" | cut -d "=" -f 2
							HSTSmaxage=`echo $line | grep -iEo "max-age=[0-9]+" | cut -d "=" -f 2` ;;
			*Public-Key-Pins*)		echo $line
							HPKP="yes" ;;
			*Connection:\ close*)		echo $line
							HTTPKeepAlive="no" ;;
			*)				;;
		esac
	done < $TMP
	rm $TMP
	
echo $HSTS $HPKP $HTTPKeepAlive
	echo "\n"
	if [ $HSTS = "yes" ] ; then
		echo $HSTSmaxage
		echo test
	fi
	echo "\n"

fi
#exit 0
for i in $TEST_PROTO
do
	CIPHER="ALL"
	TEST_CIPHER="init"
	CIPHER_LIST="Liste der Cipher-Suites:"

	while [ "$TEST_CIPHER" != "" ] && [ "$TEST_CIPHER" != "0000" ] || [ "$TEST_CIPHER" = "init" ]
	do
		CIPHER=$CIPHER:-$TEST_CIPHER
		TEST_CIPHER=`echo quit | $OPENSSLPATH s_client -$i $OPTIONS $SERVER:$PORT -cipher $CIPHER 2>&1 \
			| grep -E "Cipher.*:.*-.*" | awk '{print $3}'`

		if [ "$TEST_CIPHER" != "0000" ] && [ "$TEST_CIPHER" != "" ]; then
			CIPHER_LIST="$CIPHER_LIST\n$TEST_CIPHER"
		fi
	done

	echo "PROTO: $i\n$CIPHER_LIST\n\n"
done

get_dhparams
print_dhparams
get_servername
scan_dhprimesfile

