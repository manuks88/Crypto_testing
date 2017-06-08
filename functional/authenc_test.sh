#!/bin/bash
#Authenc has 4 parts in the key, the static_Key,encryption key size identifier,HMAC key and then the cipher key
#Easiest cipher, take data and encrypt using key, decrypt using the encypted text.
#IV cannot be null.
#Assoc and Tag can be null.

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

static_key="08000100"
key_128="44dd26da9d1f108a3c2680bae28f83e0" 
key_192="9040b222c258c48f9e5ab577233c149ceb5d6283ea3a6fc6"
key_256="45143780502c90cc11055ea65f1e016fb04c35b4d11b8c8d829843a310feda9d"

declare -a key_leng=("128" "192" "256")
declare -a auth_name=("authenc(hmac(sha1),cbc(aes))" "authenc(hmac(sha224),cbc(aes))" "authenc(hmac(sha256),cbc(aes))" "authenc(hmac(sha384),cbc(aes))" "authenc(hmac(sha512),cbc(aes))")
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
	Static_Key=$static_key
	AEAD_Name=$AEAD_name
	Tag_len=$taglen
        Keylen=$keylen
	Enc_Key_leng=$enc_key_leng
	Enc_Key=$enc_key
        Key=$key
	HMAC_Size=$hmac_key_size
	HMAC_Key=$hmac_key
        IV_Size=$iv_size
        IV=$iv
	Assoc_Size=$assoc_size
	Assoc_Data=$assoc
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

function authenc_test()
{
	ciphertype=$1
	aligned=$2
	stream=$3
	splice=$4

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
		iv_size=2
		iv=$(tr -c -d "0-9a-f" < /dev/urandom | head -c $iv_size)
	}	
	fi

	for (( iter=1;iter<$user_input;iter++ ))
	{
		for data_item in "${plain_data[@]}"
		do
		{
			AEAD_name=${auth_name["$[RANDOM % ${#auth_name[@]}]"]}
			if [[ "$AEAD_name" == *sha1* ]]
		        then
		        {
				taglen=$((( RANDOM % 20 )))
		        }
		        elif [[ "$AEAD_name" == *sha224* ]]
		        then
		        {
				taglen=$((( RANDOM % 28 )))
		        }
		        elif [[ "$AEAD_name" == *sha256* ]]
		        then
		        {
				taglen=$((( RANDOM % 32 )))
		        }
		        elif [[ "$AEAD_name" == *sha384* ]]
		        then
		        {
				taglen=$((( RANDOM % 48 )))
		        }
		        elif [[ "$AEAD_name" == *sha512* ]]
		        then
		        {
				taglen=$((( RANDOM % 64 )))
		        }
		        fi

			keylen=${key_leng["$[RANDOM % ${#key_leng[@]}]"]}
			eval enc_key=\$key_$keylen

			if [[ $keylen == "128" ]]
			then
			{
				enc_key_leng="00000010"
			}
			elif [[ $keylen == "192" ]]
			then
			{
				enc_key_leng="00000018"
			}
			elif [[ $keylen == "256" ]]
			then
			{
				enc_key_leng="00000020"
			}
			fi

			if [ -z "$taglen" ]
			then
			{
				taglen="0"
			}
			fi

			hmac_key_size=$((( RANDOM % 40 )))
			hmac_key=$(tr -c -d "0-9a-f" < /dev/urandom | head -c $hmac_key_size)

			key=$static_key$enc_key_leng$hmac_key$enc_key
		
			assoc_size=$((( RANDOM % 128 )))
			assoc=$(tr -c -d "0-9a-f" < /dev/urandom | head -c $assoc_size)

			ecmd="$KCAPI -x $ciphertype $aligned $stream $splice -e -c \"$AEAD_name\" -i \"$iv\" -k \"$key\" -p \"$data_item\" -a \"$assoc\" -l \"$taglen\""
			
			enc=$($KCAPI -x $ciphertype $aligned $stream $splice -e -c "$AEAD_name" -i "$iv" -k "$key" -p "$data_item" -a "$assoc" -l $taglen 2> /dev/null)

			actual_taglen=$(((taglen * 2) + 1))
                        encrypted=$(echo -n "$enc" | rev | cut -c $actual_taglen- | rev)
                        encrypt_len=$(echo -n "$enc" | wc -m)
                        tag_del=$(((taglen * 2) - 1))
                        tag_del_count=$((encrypt_len - tag_del))
                        tag_data=$(echo -n "$enc" | cut -c $tag_del_count-)			

			dcmd="$KCAPI -x $ciphertype $aligned $stream $splice -c \"$AEAD_name\" -i \"$iv\" -k \"$key\" -a \"$assoc\" -q \"$encrypted\" "
			dec=$($KCAPI -x $ciphertype $aligned $stream $splice -c "$AEAD_name" -i "$iv" -k "$key" -a "$assoc" -q "$encrypted" 2> /dev/null)

#			printdebug
			check_fail "fail"
			check_fail "WR"

			echo "$dec"|grep -i "fail" > /dev/null
			if [ $? == "0" ]
			then
			{
				echo -e "${error}\nTool failed.${off}\n"
				echo -e "ECMD:$ecmd\nDCMD:$dcmd\nENCRYPTED:$enc\nDECRYPTED:$dec\nEXPECTED:$data_item" > fail_authenc.log
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
				echo -e "ECMD:$ecmd\nDCMD:$dcmd\nENCRYPTED:$enc\nDECRYPTED:$dec\nEXPECTED:$data_item" > fail_authenc.log
				echo -e "${debug}Data and decrypted data files : /tmp/$data_file.txt,/tmp/$decr_file.txt${off}"
                                exit 1
                        }
                        fi
			rm -rf /tmp/$data_file.txt /tmp/$decr_file.txt
		}
		done
	}
}

declare -a options=("" "-s" "-v" "-s -v" "-m" "-m -s" "-m -v" "-m -s -v")

for ciphertype in 2 10
{
        for option in "${options[@]}"
        {
                if [[ $option == "-s" ]]
                then
                {
                        Test="Stream"
                }
                elif [[ $option == "-v" ]]
                then
                {
                        Test="Splice"
                }
                elif [[ $option == "-s -v" ]]
                then
                {
                        Test="Stream-Splice"
                }
                elif [[ $option == "-m" ]]
                then
                {
                        Test="Aligned"
                }
                elif [[ $option == "-m -s" ]]
                then
                {
                        Test="Aligned Stream"
                }
                elif [[ $option == "-m -v" ]]
                then
                {
                        Test="Aligned Splice"
                }
                elif [[ $option == "-m -s -v" ]]
                then
                {
                        Test="Aligned Stream-Splice"
                }
                elif [[ -z $option ]]
                then
                {
                        Test=""
                }
                fi

                if [[ "$ciphertype" == "2" ]]
                then
                {
                        type_test="AEAD"
                        echo -e "${GREEN}$type_test $Test${end}"
                        authenc_test $ciphertype $option
                }
                else
                {
                        type_test="AIO AEAD"
                        echo -e "${GREEN}$type_test $Test${end}"
                        authenc_test $ciphertype $option
                }
                fi
        }
}

