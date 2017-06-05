#!/bin/bash
#CBC supports 128,192 & 256 bit keys.
#Easiest cipher, take data and encrypt using key, decrypt using the encypted text.
#IV can be null.

if [ $# -ne 1 ]
then
{
        echo -e "Provide number of iterations."
        exit 1
}
fi
user_input=$1
#Color
off='\033[0m'
error='\e[0;31m'
pass='\033[0;32m'
heading='\033[1;33m'
debug='\033[0;36m'

RED="\x1B[31m"
GREEN="\x1B[01;92m"
end="\x1B[0m"

key_128="44dd26da9d1f108a3c2680bae28f83e0" 
key_192="9040b222c258c48f9e5ab577233c149ceb5d6283ea3a6fc6"
key_256="45143780502c90cc11055ea65f1e016fb04c35b4d11b8c8d829843a310feda9d"

declare -a key_leng=("128" "192" "256")
#declare -a data_input=("18913843a33d6e8f9b1aa033d8803730")
readarray data_input < $(pwd)/data_file.txt

#Test Binary path
KCAPI="/root/libkcapi-0.13.0/test/kcapi"
#KCAPI="/root/Documents/libkcapi-0.13.0/test/kcapi"
#----------------------------------------------------------------------------------------------------------------------------------------------

count=0
for data_item in "${data_input[@]}"
{
        k=`echo $data_item | xxd -c 35 | awk -F ':' '{print $2}' |awk '{$NF="";sub(/[ \t]+$/,"")}1'|tr -d '\n'|tr -d ' '`
        null_count="3"
        data_count="0"
        tot_count=$((data_count + null_count))
        plain_data[$count]=`echo $k | rev|cut -c $tot_count-|rev`
        count=$((count+1))
}

function printdebug()
{
        echo -e "${debug}
        Keylen=$keylen
        Key=$key
        IV_Size=$iv_size
        IV=$iv
        Encrypted=$enc
	PlainData=$data_item
        Decrypted=$dec
        ECMD=$ecmd
        DCMD=$dcmd${off}\n"
}

function check_fail()
{
        dmesg | grep -i $1 > /dev/null
        if [ $? == "0" ]
        then
        {
                echo -e "${error}An error is seen, check dmesg.${off}"
                printdebug
                exit 1
        }
        fi
}

function cbc_test()
{
	ciphertype=$1
	aligned=$2
	stream=$3
	splice=$4
	AEAD_name="cbc(aes)"


        data_file=$(tr -c -d "0-9a-z" < /dev/urandom | head -c 5)
        decr_file=$(tr -c -d "0-9a-z" < /dev/urandom | head -c 5)
        touch /tmp/$data_file.txt
        touch /tmp/$decr_file.txt

	iv_size=$(( RANDOM % 100 ))
	if [ $iv_size != 0 ]
	then
	{
		iv=$(tr -c -d "0-9a-f" < /dev/urandom | head -c $iv_size)
	}
	else
	{
		iv=""
	}
	fi

	for (( iter=1;iter<$user_input;iter++ ))
	{
		for data_item in "${plain_data[@]}"
		do
		{
			keylen=${key_leng["$[RANDOM % ${#key_leng[@]}]"]}
			eval key=\$key_$keylen

			ecmd="$KCAPI -x $ciphertype $aligned $stream $splice -e -c \"$AEAD_name\" -i \"$iv\" -k \"$key\" -p \"$data_item\""
			
			enc=$($KCAPI -x $ciphertype $aligned $stream $splice -e -c "$AEAD_name" -i "$iv" -k "$key" -p "$data_item" 2> /dev/null)
			encrypted=$(echo -n $enc)
			

			dcmd="$KCAPI -x $ciphertype $aligned $stream $splice -c \"$AEAD_name\" -i \"$iv\" -k \"$key\" -q \"$encrypted\" "
			dec=$($KCAPI -x $ciphertype $aligned $stream $splice -c "$AEAD_name" -i "$iv" -k "$key" -q "$encrypted" 2> /dev/null)

			check_fail "fail"
			check_fail "WR"

			echo "$dec"|grep -i "fail" > /dev/null
			if [ $? == "0" ]
			then
			{
				echo -e "${error}\nTool failed.${off}\n"
				echo -e "ECMD:$ecmd\nDCMD:$dcmd\nENCRYPTED:$enc\nDECRYPTED:$dec\nEXPECTED:$data_item" > fail_cbc.log
				exit 1
			}
			fi
                        echo -n "$data_item" > /tmp/$data_file.txt
                        echo -n "$dec" > /tmp/$decr_file.txt
                        diff /tmp/$data_file.txt /tmp/$decr_file.txt > /dev/null
                        if [ $? -ne 0 ]
                        then
                        {
                                echo -e "${RED}Test failed.${end}"
				echo -e "ECMD:$ecmd\nDCMD:$dcmd\nENCRYPTED:$enc\nDECRYPTED:$dec\nEXPECTED:$data_item" > fail_cbc.log
				echo -e "${debug}Data and decrypted data files : /tmp/$data_file.txt,/tmp/$decr_file.txt${off}"
                                exit 1
                        }
                        fi
		}
		done
	}
}
cbc_test 1
#cbc_test 9 -s 
#cbc_test 9 -v 
#cbc_test 1 -s 
#cbc_test 1 -v
#cbc_test 1 "" -v -s 
#cbc_test 9 -m -v -s 
