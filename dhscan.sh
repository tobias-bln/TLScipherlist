#!/bin/sh

#SERVER=$1
#PORT=$2

# SKE = ServerKeyExchange
INSKE=0
TMP="/tmp/dhscan.tmp"
script=$0
basename="$(dirname $script)"
#PRIMES="$basename/primes.txt"
PRIMES="/Users/tobias/Pydio/My Files/dhscan/primes.txt"


#echo quit | /usr/local/opt/openssl/bin/openssl s_client -debug -msg $OPTIONS $SERVER:$PORT -cipher DHE\
echo quit | $OPENSSLPATH s_client -debug -msg $OPTIONS $SERVER:$PORT -cipher DHE\
            > $TMP 2> /dev/null

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

# remove spaces from hexdump
SKE=`echo $SKE | tr -d ' '`

## get p
LengthPHex=`echo $SKE | cut -c 9-12`
LengthP=`echo $((16#$LengthPHex))`
PHex=`echo $SKE | cut -c 13-$((13 - 1 + $LengthP * 2))`

## get g
LengthGHex=`echo $SKE | cut -c $((13 + $LengthP * 2))-$((13 + 3 + $LengthP * 2))`
LengthG=`echo $((16#$LengthGHex))`
GHex=`echo $SKE | cut -c $((13 + 4 + $LengthP * 2))-$((13 + 3 + $LengthP * 2 + $LengthG * 2))`

## get pubkey
LengthPubkeyHex=`echo $SKE | cut -c $((13 + 4 + $LengthP * 2 + $LengthG * 2))-$((13 + 4 + 3 + $LengthP * 2 + $LengthG * 2))`
LengthPubkey=`echo $((16#$LengthPubkeyHex))`
PubkeyHex=`echo $SKE | cut -c $((13 + 4 + 4 + $LengthP * 2 + $LengthG * 2 ))-$((13 + 4 + 3 + $LengthP * 2 + $LengthG * 2 + $LengthPubkey * 2))`


## print p,g,pubkey
if [ $VERBOSE = "yes" ] ; then
echo "\
Length of p: $LengthP Bytes\n\
p:\n\
$PHex\n\n\
Length of g: $LengthG Bytes\n\
g:\n\
$GHex\n\n\
Length of Pubkey: $LengthPubkey Bytes\n\
Pubkey:\n\
$PubkeyHex\n"
fi

## scan primes file

if [ $PORT = "443" ] ; then
	ServerNameTLS="`curl --connect-timeout 5 -sI  https://$SERVER |\
        	        grep "Server:" | cut -d " " -f 2- | tr " " "_" | tr -d "[:cntrl:]"`"
	ServerName="`curl --connect-timeout 5 -sI  http://$SERVER |\
	             grep "Server:" | cut -d " " -f 2- | tr " " "_" | tr -d "[:cntrl:]"`"
fi

if [ "$ServerNameTLS" = "" ] ; then
	ServerNameTLS="UNKNOWN"
fi

if [ "$ServerName" = "" ] ; then
	ServerName="UNKNOWN"
fi

echo Server Name is: $ServerNameTLS
echo Server Name may be: $ServerName

while read line ;do
	if [[ $line =~ ^$PHex ]] ; then
                if [[ $line =~ " $ServerNameTLS " ]] || [[ $line =~ "$ServerNameTLS"$  ]] ; then
			echo "This Server is known to use these prime."
			echo "Servers, known to use these prime: `echo $line | cut -d \" \" -f 2-`"
		else
			echo "This Server is NOT known to use these prime."
			echo "Servers, known to use these prime: `echo $line | cut -d \" \" -f 2-`"
		fi
        fi
done < $PRIMES

