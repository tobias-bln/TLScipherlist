#!/bin/sh

check_sslversion() {

    if [ $OPENSSLv -lt 102 ] ; then
        echo "You should update OpenSSL!\nSome tests will not work unless you update to OpenSSL version 1.0.2 or later.\n"
    fi
}

print_keyparams() {

    echo Key Parameters:
    echo | $OPENSSLPATH s_client $OPTIONS $SERVER:$PORT -cipher "DH" \
        2>/dev/null | grep -iE "key.*bit.*"
    echo "\n"
}


cipher_scan() {

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

}

get_httpheaders() {

    HSTS="no"
    HPKP="no"
    HTTPKeepAlive="yes"

    echo "Check for HTTP Headers:"
    curl -sI https://$SERVER > $TMP
    while read line
    do
        case $line in
            *Strict-Transport-Security*)	echo $line
                                            HSTS="yes"
                                            #echo $line | grep -iEo "max-age=[0-9]+" | cut -d "=" -f 2
                                            HSTSmaxage=`echo $line | grep -iEo "max-age=[0-9]+" | cut -d "=" -f 2` ;;

            *Public-Key-Pins*)              echo $line
                                            HPKP="yes"
                                            HPKPmaxage=`echo $line | grep -iEo "max-age=[0-9]+" | cut -d "=" -f 2`;;

            *Connection:\ close*)           HTTPKeepAlive="no" ;;

            *)                              ;;
        esac
    done < $TMP
    rm $TMP

    #echo $HSTS $HPKP $HTTPKeepAlive
    echo ""

    if [ $HSTS = "yes" ] ; then
        if [ $HSTSmaxage -ge 31536000 ] ; then
            echo "\tgood:\tStrict-Transport-Security max-age is >= 31536000 (1 year)"
        else
            echo "\t!:\tStrict-Transport-Security max-age is < 31536000 (1 year)"
        fi
    else
        echo "\tbad:\tno HTTP-Strict-Transport-Security-Header"
    fi

    if [ $HPKP = "yes" ] ; then
        if [ $HPKPmaxage -ge 5184000 ] ; then
            echo "\tgood:\tPublic-Key-Pins max-age is >= 5184000 (60 days)"
        else
            echo "\t!:\tPublic-Key-Pins max-age is < 5184000 (60 days)"
        fi
    else
        echo "\tbad:\tno HTTP-Public-Key-Pins-Header"
    fi

    if [ $HTTPKeepAlive = "yes" ] ; then
        echo "\tgood:\tHTTP Keep-Alive on"
    else
        echo "\t!:\tHTTP Keep-Alive off "
    fi

    echo "\n"

}

get_dhparams() {

    INSKE=0

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
        echo "ERROR: ssl handshake failure (dhparams)"
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

}

print_dhparams() {

## print p,g,pubkey
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

}

get_servername() {

    if [ $PORT = "443" ] ; then
        ServerNameTLS="`/usr/bin/curl --connect-timeout 5 -sI  https://$SERVER |\
                        grep "Server:" | cut -d " " -f 2- | tr " " "_" | tr -d "[:cntrl:]"`"
        ServerName="`/usr/bin/curl --connect-timeout 5 -sI  http://$SERVER |\
                    grep "Server:" | cut -d " " -f 2- | tr " " "_" | tr -d "[:cntrl:]"`"
    fi

    if [ "$ServerNameTLS" = "" ] ; then
        ServerNameTLS="UNKNOWN"
    fi

    if [ "$ServerName" = "" ] ; then
        ServerName="UNKNOWN"
    fi

# todo: nmap -sV example.com -p

    echo Server Name is: $ServerNameTLS
    echo Server Name may be: $ServerName

}

scan_dhprimesfile() {

    ## scan primes file
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

}
