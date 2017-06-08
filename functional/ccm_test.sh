#!/bin/bash
#CCM supports 128,192 & 256 bit keys.
#Tag length supported is '4' '6' '8' '10' '12' '14' '16'
#While giving data input to libkcapi make sure to take care of the "new line" character that is added
#from bash. So we convert the input to hex and remove the trailing "new line" character.
#AEAD requires tag length. The tag will be appended to the encrypted output. So based on the taglength
#the tag_data needs to be extracted from the output".
#During decryption we take the delta of output after removing tag_data and use this tag_data to get original
#text.

#USE -y for 'Test long AD with AEAD cipher' with -s option. Does _not_ work with -v"

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

ccm_14=('8f3a644574a25c')
ccm_16=('85f9724b45004dcb')
ccm_18=('7b3e0077dc1df1ac96')
ccm_20=('7b3c84ffc3ec25fbd375')
ccm_22=('6af7bde66d2de9c8169b45')
ccm_24=('36775f67b9fcf0918d9206e6')
ccm_26=('f82e04b8d08a776ba5ee1fdcfb')

declare -a key_leng=("128" "192" "256")
declare -a tag_leng=("4" "6" "8" "10" "12" "14" "16")
declare -a assoc_leng=("1" "2" "3" "4" "5" "6" "7" "8")
declare -a nonce_leng=("14" "16" "18" "20" "22" "24" "26")

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
        Nonce_size=$noncelen
        Nonce=$nonce
        Assoc_len=$assoclen
        Assoc=$assoc
        Taglen=$taglen
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

function ccm_test()
{
	ciphertype=$1
	aligned=$2
	stream=$3
	splice=$4
	AEAD_name="ccm(aes)"

        data_file=$(tr -c -d "0-9a-z" < /dev/urandom | head -c 5)
        decr_file=$(tr -c -d "0-9a-z" < /dev/urandom | head -c 5)
        touch /tmp/$data_file.txt
        touch /tmp/$decr_file.txt

	for (( iter=1;iter<$user_input;iter++ ))
	{
		for data_item in "${plain_data[@]}"
		do
		{
			keylen=${key_leng["$[RANDOM % ${#key_leng[@]}]"]}
			eval key=\$key_$keylen
			assoclen=${assoc_leng["$[RANDOM % ${#assoc_leng[@]}]"]}
			eval assoc=\$assoc_$assoclen
			noncelen=${nonce_leng["$[RANDOM % ${#nonce_leng[@]}]"]}
			eval nonce=\$ccm_$noncelen
			taglen=${tag_leng["$[RANDOM % ${#tag_leng[@]}]"]}
			
			ecmd="$KCAPI -x $ciphertype $aligned $stream $splice -e -c \"$AEAD_name\" -n \"$nonce\" -k \"$key\" -a \"$assoc\" -p \"$data_item\" -l \"$taglen\""
			
			enc=$($KCAPI -x $ciphertype $aligned $stream $splice -e -c "$AEAD_name" -n "$nonce" -k "$key" -a "$assoc" -p "$data_item" -l "$taglen" 2> /dev/null)
			
			actual_taglen=$(((taglen * 2) + 1))
                        encrypted=$(echo -n "$enc" | rev | cut -c $actual_taglen- | rev)
                        encrypt_len=$(echo -n "$enc" | wc -m)
                        tag_del=$(((taglen * 2) - 1))
                        tag_del_count=$((encrypt_len - tag_del))
                        tag_data=$(echo -n "$enc" | cut -c $tag_del_count-)

			dcmd="$KCAPI -x $ciphertype $aligned $stream $splice -c \"$AEAD_name\" -n \"$nonce\" -k \"$key\" -a \"$assoc\" -q \"$encrypted\" -t \"$tag_data\""
			dec=$($KCAPI -x $ciphertype $aligned $stream $splice -c "$AEAD_name" -n "$nonce" -k "$key" -a "$assoc" -q "$encrypted" -t "$tag_data" 2> /dev/null)

			check_fail "fail"
			check_fail "WR"

			echo "$dec"|grep -i "fail" > /dev/null
			if [ $? == "0" ]
			then
			{
				echo -e "${error}\nTool failed.${off}\n"
				echo -e "ECMD:$ecmd\nDCMD:$dcmd\nENCRYPTED:$enc\nDECRYPTED:$dec\nEXPECTED:$data_item" > fail_ccm.log
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
				echo -e "ECMD:$ecmd\nDCMD:$dcmd\nENCRYPTED:$enc\nDECRYPTED:$dec\nEXPECTED:$data_item" > fail_ccm.log
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
                fi

                if [[ "$ciphertype" == "2" ]]
                then
                {
                        type_test="AEAD"
                        echo -e "${GREEN}$type_test $Test${end}"
                        ccm_test $ciphertype $option
                }
                else
                {
                        type_test="AIO AEAD"
                        echo -e "${GREEN}$type_test $Test${end}"
                        ccm_test $ciphertype $option
                }
                fi
        }
}
