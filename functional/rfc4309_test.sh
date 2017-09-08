#!/bin/bash
#GCM_RFC4106 supports 128,192 & 256 bit keys.But make sure the take into consideration the SALT value.
#128 bit key is 16 octet's so use use 128bit key for encryption a total of 19 octets is key. The remaining 3
#octets is for the SALT.
#128 key = 152bits = 38char's
#192 key = 216bits = 54char's
#256 key = 280bits = 70char's
#Tag length supported is "8" "12" "16"
#While giving data input to libkcapi make sure to take care of the "new line" character that is added
#from bash. So we convert the input to hex and remove the trailing "new line" character.
#Assoc data is a combination of IV and assoc data.
#AEAD requires tag length. The tag will be appended to the encrypted output. So based on the taglength
#the tag_data needs to be extracted from the output".
#During decryption we take the delta of output after removing tag_data and use this tag_data to get original
#text.

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

#Key + SALT, so length is more.
key_128="f196f976378764463ec767cf7bd2576280e3b2"
key_192="3b41d15cf0342dc2c996c0a36780654b8d0f66028ec5186e5e350c"
key_256="15fc63859bd3f3383b7f204a1181cc3914a38c1e18b46eea83a4addbd9420f7742a038"

assoc_1=""
assoc_2="0dbe914e"
assoc_32="230f403d65a965854b2490846074e43f"
assoc_40="7c19625d8ae5e250ddfd606784b9d72474c99b71"

declare -a key_leng=("128" "192" "256")
declare -a tag_leng=("8" "12" "16")

#declare -a data_input=("18913843a33d6e8f9b1aa033d8803730")
readarray data_input < $(pwd)/data_file.txt

#Test Binary path
KCAPI="/usr/local/bin/kcapi"
#KCAPI="/root/libkcapi-0.13.0/test/kcapi"
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
        IV_size=$iv_size
	IV=$iv
        Assoc_len=$assoclen
	Assoc_data=$assoc_data
        Assoc=$assoc
        Taglen=$taglen
	Tag_length=$tag_del_count
        Tag_data=$tag_data
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

function rfc4309_test()
{
	ciphertype=$1
	aligned=$2
	stream=$3
	splice=$4
	AEAD_name="rfc4309(ccm(aes))"

        data_file=$(tr -c -d "0-9a-z" < /dev/urandom | head -c 5)
        decr_file=$(tr -c -d "0-9a-z" < /dev/urandom | head -c 5)
        touch /tmp/$data_file.txt
        touch /tmp/$decr_file.txt

	iv_size=$((( RANDOM % 20 )+ 1))
	if [ $iv_size == 1 ]
	then
	{
		iv_size=2
	}
	fi
	iv=$(tr -c -d "0-9a-f" < /dev/urandom | head -c $iv_size)
	if [ "$iv_size" -gt "17" ]
	then
	{
		assoc_size=$((40 - iv_size))
		assoc_data=$(tr -c -d "0-9a-f" < /dev/urandom | head -c $assoc_size)
	}
	else
	{
		assoc_size=$((32 - iv_size))
                assoc_data=$(tr -c -d "0-9a-f" < /dev/urandom | head -c $assoc_size)
	}
	fi

	for (( iter=0;iter<$user_input;iter++ ))
	{
		for data_item in "${plain_data[@]}"
		do
		{
			keylen=${key_leng["$[RANDOM % ${#key_leng[@]}]"]}
			eval key=\$key_$keylen
			assoc=${assoc_data}${iv}
			data_leng=$(echo -n $data_item | wc -m)
			taglen=${tag_leng["$[RANDOM % ${#tag_leng[@]}]"]}
			
			ecmd="$KCAPI -x $ciphertype $aligned $stream $splice -e -c \"$AEAD_name\" -i \"$iv\" -k \"$key\" -a \"$assoc\" -p \"$data_item\" -l \"$taglen\""
			
			enc=$($KCAPI -x $ciphertype $aligned $stream $splice -e -c "$AEAD_name" -i "$iv" -k "$key" -a "$assoc" -p "$data_item" -l "$taglen" 2> /dev/null)
			
                        encrypt_leng=$(echo -n "$enc" | wc -m)
			encrypted_data_leng=$((encrypt_leng - data_leng))
			encrypted_data_leng=$((encrypted_data_leng + 1))
			encrypted=$(echo "$enc" | rev | cut -c $encrypted_data_leng- | rev)
			tag_del_count=$((data_leng + 1))
			tag_data=$(echo -n "$enc" | cut -c $tag_del_count-)

			dcmd="$KCAPI -x $ciphertype $aligned $stream $splice -c \"$AEAD_name\" -i \"$iv\" -k \"$key\" -a \"$assoc\" -q \"$encrypted\" -t \"$tag_data\""
			dec=$($KCAPI -x $ciphertype $aligned $stream $splice -c "$AEAD_name" -i "$iv" -k "$key" -a "$assoc" -q "$encrypted" -t "$tag_data" 2> /dev/null)

			check_fail "fail"
			check_fail "WR"
			check_fail "trace"
			check_fail "chcr:"

			echo "$dec"|grep -i "fail" > /dev/null
			if [ $? == "0" ]
			then
			{
				echo -e "${error}\nTool failed.${off}\n"
				echo -e "ECMD:$ecmd\nDCMD:$dcmd\nENCRYPTED:$enc\nDECRYPTED:$dec\nEXPECTED:$data_item" > fail_rfc4309.log
				exit 1
			}
			fi
			echo -n "$data_item" > /tmp/$data_file.txt
                        echo -n "$dec" > /tmp/$decr_file.txt
                        diff /tmp/$data_file.txt /tmp/$decr_file.txt > /dev/null
                        if [ $? -ne 0 ]
                        then
                        {
                                echo -e "${error}Test failed.${off}"
				echo -e "ECMD:$ecmd\nDCMD:$dcmd\nENCRYPTED:$enc\nDECRYPTED:$dec\nEXPECTED:$data_item" > fail_rfc4309.log
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
	                rfc4309_test $ciphertype $option
	        }
	        else
	        {
	                type_test="AIO AEAD"
	                echo -e "${GREEN}$type_test $Test${end}"
	                rfc4309_test $ciphertype $option
	        }
	        fi
	}
}
