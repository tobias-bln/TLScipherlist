#!/bin/sh

# echo quit | openssl s_client -connect www.example.com:443 -cipher ALL 2>&1 | grep -E "Cipher.*:" | awk '{print $3}'

# Linux add -e -> echo -e

# OS X:

SERVER=$1
PORT=$2
SSLbin=$3

TEST_PROTO="ssl2 ssl3 tls1 tls1_1 tls1_2"

OPTIONS="-connect"

case "$SSLbin" in
	osx) OPENSSLPATH="/usr/bin/openssl" ;;
	brew) OPENSSLPATH="/usr/local/opt/openssl/bin/openssl" ;;
	*) OPENSSLPATH="openssl" ;;
esac

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

	echo "Check for HSTS and HPKP Headers:"
	curl -s -I https://$SERVER | grep -iE "Strict-Transport-Security|Public-Key-Pins"
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

