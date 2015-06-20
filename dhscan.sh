#!/bin/sh

HOST=$1
PORT=$2

INSKE=0
TMP="/tmp/dhscan.tmp"
#ERR="/tmp/dhscan.err"
script=$0
basename="$(dirname $script)"
PRIMES="$basename/primes.txt"


echo quit | /usr/local/opt/openssl/bin/openssl s_client -debug -msg -connect $HOST:$PORT -cipher DHE > $TMP 2> /dev/null

if [ "$?" = "0" ] ; then

	while read line ;do

		if [[ ! $line =~ ^([a-f0-9]{2} [a-f0-9]{2}) ]] && [[ !  $line =~ ^([a-f0-9]{2}$)  ]] ; then
			INSKE=0
		fi

		if [ $INSKE != 0 ] ; then
			SKE=$SKE" "$line
		fi

		if [[ $line =~ ^\<\<\<.*ServerKeyExchange$ ]] ; then
			INSKE=1
        	fi
	done < $TMP
else
	echo "ERROR: ssl handshake failure"
	rm $TMP
	exit 1
fi
rm $TMP

SKE=`echo $SKE | tr -d ' '`

## get p
LengthPHex=`echo $SKE | cut -c 9-12`
LengthP=`echo $((16#$LengthPHex))`
echo "Length of p: $LengthP Bytes"

echo p:
PHex=`echo $SKE | cut -c 13-$((13 - 1 + $LengthP * 2))`
echo "$PHex\n"

## get g
LengthGHex=`echo $SKE | cut -c $((13 + $LengthP * 2))-$((13 + 3 + $LengthP * 2))`
LengthG=`echo $((16#$LengthGHex))`
echo "Length of g: $LengthG Bytes"

echo g:
GHex=`echo $SKE | cut -c $((13 + 4 + $LengthP * 2))-$((13 + 3 + $LengthP * 2 + $LengthG * 2))`
echo "$GHex\n"

## get pubkey
LengthPubkeyHex=`echo $SKE | cut -c $((13 + 4 + $LengthP * 2 + $LengthG * 2))-$((13 + 4 + 3 + $LengthP * 2 + $LengthG * 2))`
LengthPubkey=`echo $((16#$LengthPubkeyHex))`
echo "Length of Pubkey: $LengthPubkey Bytes"

echo Pubkey:
PubkeyHex=`echo $SKE | cut -c $((13 + 4 + 4 + $LengthP * 2 + $LengthG * 2 ))-$((13 + 4 + 3 + $LengthP * 2 + $LengthG * 2 + $LengthPubkey * 2))`
echo "$PubkeyHex\n"


## scan primes file

ServerNameTLS="`curl --connect-timeout 5 -sI  https://$HOST | grep "Server:" | cut -d " " -f 2- | tr " " "_" | tr -d "[:cntrl:]"`"
ServerName="`curl --connect-timeout 5 -sI  http://$HOST | grep "Server:" | cut -d " " -f 2- | tr " " "_" | tr -d "[:cntrl:]"`"

if [ "$ServerNameTLS" = "" ] ; then
	ServerNameTLS="UNKNOWN"
fi

echo Server Name is: $ServerNameTLS

if [ "$ServerName" = "" ] ; then
	ServerName="UNKNOWN"
fi
echo Server Name may be: $ServerName


while read line ;do

	#if [[ $line =~ ^$PHex ]] && [[ $line =~ $ServerName ]] ; then
	if [[ $line =~ ^$PHex ]] ; then
		#echo found. $ServerName
                if [[ $line =~ " $ServerNameTLS " ]] || [[ $line =~ "$ServerNameTLS"$  ]] ; then
			echo "This Server is known to use these prime."
			echo "Servers, known to use these prime: `echo $line | cut -d \" \" -f 2-`"
		else
			echo "This Server is NOT known to use these prime."
			echo "Servers, known to use these prime: `echo $line | cut -d \" \" -f 2-`"
		fi
        fi
	#echo $line
done < $PRIMES

