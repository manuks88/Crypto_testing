#!/bin/bash
#GCM_RFC4106 supports 128,192 & 256 bit keys.But make sure the take into consideration the SALT value.
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

#Key + SALT, so length is more.
key_128="0d619d0527b491484d1bfecf029be1c24226fb1a"
key_192="b815e4d98e7e91d476152c44596b02ab1f75319a15d8a6c260eafe45"
key_256="3d2a91b4607477217ce9816f8e2b4b0201c4a6900a712631250c5f4690198e2fdcf04073"

assoc_1=""
assoc_2="32578"
assoc_3="9926955637"
assoc_4="036652369429784"
assoc_5="046553862931100730565"
assoc_6="67977111399186363719828586853974"
assoc_7="944784330463044581168718752647326343924198440285"
assoc_8="3522558552215345589054024869445718308459930230810925924374337683"

declare -a key_leng=("128" "192" "256")
declare -a tag_leng=("8" "12" "16")
declare -a assoc_leng=("1" "2" "3" "4" "5" "6" "7" "8")
declare -a data_input=("18913843a33d6e8f9b1aa033d8803730")
#readarray data_input < /root/crypto_scripts/all_test/plain_data.input

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

function rfc4106_test()
{
	ciphertype=$1
	aligned=$2
	stream=$3
	splice=$4
	AEAD_name="rfc4106(gcm(aes))"

	iv_size=$((( RANDOM % 100 )+ 1))
	if [ $iv_size == 1 ]
	then
	{
		iv_size=2
	}
	fi
	iv=$(tr -c -d "0-9a-f" < /dev/urandom | head -c $iv_size)

	for (( iter=1;iter<$user_input;iter++ ))
	{
		for data_item in "${plain_data[@]}"
		do
		{
			keylen=${key_leng["$[RANDOM % ${#key_leng[@]}]"]}
			eval key=\$key_$keylen
			assoclen=${assoc_leng["$[RANDOM % ${#assoc_leng[@]}]"]}
			eval assoc_data=\$assoc_$assoclen
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

			printdebug
			check_fail "fail"
			check_fail "WR"

			echo "$dec"|grep -i "fail" > /dev/null
			if [ $? == "0" ]
			then
			{
				echo -e "${error}\nTool failed.${off}\n"
				echo -e "${heading}ECMD:${debug}$ecmd\n${heading}DCMD:${debug}$dcmd\n${heading}Encrypted:${debug}$enc\n${heading}Decrypted:${debug}$dec\n${heading}Expected:${debug}$data_item${off}"
				exit 1
			}
			fi
                        if [ $data_item != $dec ]
                        then
                        {
                                echo -e "${error}Test failed.${off}"
				echo -e "${debug}ECMD:$ecmd\nDCMD:$dcmd\nEncrypted:$enc\nDecrypted:$dec\nExpected:$data_item${off}"
                                exit 1
                        }
                        fi
		}
		done
	}
}
gcm_test 2
#gcm_test 10 -s &
#gcm_test 10 -v &
#gcm_test 2 -s &
#gcm_test 2 -v &
