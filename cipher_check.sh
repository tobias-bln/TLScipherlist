#!/bin/sh

# echo quit | openssl s_client -connect www.example.com:443 -cipher ALL 2>&1 | grep -E "Cipher.*:" | awk '{print $3}'

SERVER=$1
PORT=$2

TEST_PROTO="ssl2 ssl3 tls1 tls1_1 tls1_2"

OPTIONS="-connect"

echo -e "############################################\n# SSL-Test: $SERVER:$PORT\n############################################\n"

case "$PORT" in
	587)	OPTIONS="-starttls smtp -connect" ;;
	443)	OPTIONS="-connect" ;;
	143)	OPTIONS="-starttls imap -connect" ;;
	25)	OPTIONS="-starttls smtp -connect" ;;
	*)	echo unknown Port: $PORT
		exit 1 ;;
esac

for i in $TEST_PROTO
do
	CIPHER="ALL"
	TEST_CIPHER="init"
	CIPHER_LIST="Liste der Cipher-Suites:"

	while [ "$TEST_CIPHER" != "" ] && [ "$TEST_CIPHER" != "0000" ] || [ "$TEST_CIPHER" = "init" ]
	do
		CIPHER=$CIPHER:-$TEST_CIPHER
		TEST_CIPHER=`echo quit | openssl s_client -$i $OPTIONS $SERVER:$PORT -cipher $CIPHER 2>&1 | grep -E "Cipher.*:" | awk '{print $3}'`
		#echo $TEST_CIPHER
		#echo $CIPHER
		if [ "$TEST_CIPHER" != "0000" ] && [ "$TEST_CIPHER" != "" ]; then
			CIPHER_LIST="$CIPHER_LIST\n$TEST_CIPHER"
		fi
	done

	echo -e "PROTO: $i\n$CIPHER_LIST\n\n"

done
