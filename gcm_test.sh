#!/bin/bash
#GCM supports 128,192 & 256 bit keys.
#Tag length supported is '4' '8' '12' '13' '14' '15' '16'
#While giving data input to libkcapi make sure to take care of the "new line" character that is added
#from bash. So we convert the input to hex and remove the trailing "new line" character.
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

key_128="44dd26da9d1f108a3c2680bae28f83e0" #128 bit
key_192="9040b222c258c48f9e5ab577233c149ceb5d6283ea3a6fc6" #192 bit
key_256="45143780502c90cc11055ea65f1e016fb04c35b4d11b8c8d829843a310feda9d" #256 bit

assoc_1=""
assoc_2="32578"
assoc_3="9926955637"
assoc_4="036652369429784"
assoc_5="046553862931100730565"
assoc_6="67977111399186363719828586853974"
assoc_7="944784330463044581168718752647326343924198440285"
assoc_8="3522558552215345589054024869445718308459930230810925924374337683"

#iv="00000000000000000000000000000000"

declare -a key_leng=("128" "192" "256")
declare -a tag_leng=("4" "8" "12" "13" "14" "15" "16")
declare -a assoc_leng=("1" "2" "3" "4" "5" "6" "7" "8")
declare -a data_input=("18913843a33d6e8f9b1aa033d8803730")
#readarray data_input < /root/crypto_scripts/all_test/plain_data.input

#Test Binary path
KCAPI="/root/libkcapi-0.13.0/test/kcapi"
#KCAPI="/root/Documents/libkcapi-0.13.0/test/kcapi"

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
        Assoc=$assoc
        Taglen=$taglen
        Encrypted=$enc
        Tag_data=$tag_data
        Data_item=$data_item
        Decrypted=$dec
        ECMD=$ecmd
        DCMD=$dcmd${off}\n"
}

function gcm_test()
{
	ciphertype=$1
	aligned=$2
	stream=$3
	AEAD_name="gcm(aes)"

	iv_size=$((( RANDOM % 100 )+ 1))
	if [ $iv_size == 1 ]
	then
	{
		iv_size=2
	}
	fi
	iv=$(tr -c -d 0-9 < /dev/urandom | head -c $iv_size)

	for (( iter=1;iter<$user_input;iter++ ))
	{
		for data_item in "${plain_data[@]}"
		do
		{
			keylen=${key_leng["$[RANDOM % ${#key_leng[@]}]"]}
			eval key=\$key_$keylen
			assoclen=${assoc_leng["$[RANDOM % ${#assoc_leng[@]}]"]}
			eval assoc=\$assoc_$assoclen
			taglen=${tag_leng["$[RANDOM % ${#tag_leng[@]}]"]}
			
			ecmd="$KCAPI -x $ciphertype $aligned $stream -e -c \"$AEAD_name\" -i \"$iv\" -k \"$key\" -a \"$assoc\" -p \"$data_item\" -l \"$taglen\""
			
			enc=$($KCAPI -x $ciphertype $aligned $stream -e -c "$AEAD_name" -i "$iv" -k "$key" -a "$assoc" -p "$data_item" -l "$taglen" 2> /dev/null)
			
			actual_taglen=$(((taglen * 2) + 1))
                        encrypted=$(echo -n "$enc" | rev | cut -c $actual_taglen- | rev)
                        encrypt_len=$(echo -n "$enc" | wc -m)
                        tag_del=$(((taglen * 2) - 1))
                        tag_del_count=$((encrypt_len - tag_del))
                        tag_data=$(echo -n "$enc" | cut -c $tag_del_count-)

			dcmd="$KCAPI -x $ciphertype $aligned $stream -c \"$AEAD_name\" -i \"$iv\" -k \"$key\" -a \"$assoc\" -q \"$encrypted\" -t \"$tag_data\""
			dec=$($KCAPI -x $ciphertype $aligned $stream -c "$AEAD_name" -i "$iv" -k "$key" -a "$assoc" -q "$encrypted" -t "$tag_data" 2> /dev/null)
			printdebug

                        dmesg|grep -i "WR" > /dev/null
                        if [ $? == "0" ]
                        then
                        {
                            echo "Failed to create WR during encryption.. exiting."
                            data_len=`echo -n $data_item | wc -m`
                            echo -e "${error}Plain_data_input : $data_len${off}"
                            dmesg -c > /dev/null
                        }
			fi
			echo "$dec"|grep -i "fail" > /dev/null
			if [ $? == "0" ]
			then
			{
				echo -e "${error}\nTool failed.May have to use patch provided in bug 33073.${off}\n"
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
