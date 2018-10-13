#!/bin/bash

if [ $# -lt 1 ]
then
{
        echo "Provide file name."
        exit 1
}
fi

file_name=$1
fail_count=0
pass_count=0

if [ -f $file_name ]
then
{
	if echo $file_name | grep -iv ".rsp" > /dev/null || echo $file_name | grep -iv "xts" > /dev/null
	then
	{
		exit 1
	}
	fi
	echo -e "\nRunning test vectors from $file_name"
	test_str=$(echo $file_name | awk -F '.rsp' '{print $1}' | awk -F '/' '{print $NF}')
        enc_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	sed -n '/ENCRYPT/,/DECRYPT/p' $file_name > /tmp/$enc_file
        dec_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	sed -n '/DECRYPT/,//p' $file_name > /tmp/$dec_file

	vect_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	#Enc test
	count=$(cat /tmp/$enc_file | grep -i "COUNT" | wc -l)
	for (( i=1;i<=$count;i++ ))
	do
	{
	        rm -rf /tmp/$vect_file
	        grep -w "COUNT = $i" /tmp/$enc_file -A 5 | sed 's/\s//g' > /tmp/$vect_file
	        key=$(grep 'Key=' /tmp/$vect_file | cut -d=  -f2)
		iv=$(grep 'i=' /tmp/$vect_file | cut -d=  -f2)
	        pt=$(grep 'PT=' /tmp/$vect_file | cut -d= -f2)
		ct=$(grep 'CT=' /tmp/$vect_file | cut -d= -f2)
		dulen=$(grep 'DataUnitLen=' /tmp/$vect_file | cut -d= -f2)

		if (( $dulen % 16 == 0 ))
		then
		{

			if [ -z "$iv" ]
			then
			{
				enc_data=$(kcapi -x 1 -e -c "xts(aes)" -p $pt -k $key)
			}
			else
			{ 
				enc_data=$(kcapi -x 1 -e -c "xts(aes)" -p $pt -k $key -i $iv)
			}
			fi
		
			if [ "$enc_data" != "$ct" ]
			then
			{
				echo -e "\nXTS Encryption failed for $file_name, vector count $i"
				
				echo "Exp CipherText : $ct"
				echo "Got CipherText : $enc_data"
				exit 1
				fail_count=$((fail_count+1))
			}
			else
			{
				pass_count=$((pass_count+1))
			}
			fi
		}
		fi
	
	}
	done
	echo "Total $test_str Encryption pass count = $pass_count, fail count = $fail_count"
	#Decryption
	fail_count=0
	pass_count=0
	count=$(cat /tmp/$dec_file | grep -i "COUNT" | wc -l)
	for (( i=1;i<=$count;i++ ))
	do
	{
	        rm -rf /tmp/$vect_file
	        grep -w "COUNT = $i" /tmp/$dec_file -A 5 | sed 's/\s//g' > /tmp/$vect_file
	        key=$(grep 'Key=' /tmp/$vect_file | cut -d=  -f2)
		iv=$(grep 'i=' /tmp/$vect_file | cut -d=  -f2)
	        pt=$(grep 'PT=' /tmp/$vect_file | cut -d= -f2)
		ct=$(grep 'CT=' /tmp/$vect_file | cut -d= -f2)
		dulen=$(grep 'DataUnitLen=' /tmp/$vect_file | cut -d= -f2)

		if (( $dulen % 16 == 0 ))
		then
		{
			if [ -z "$iv" ]
			then
			{
				dec_data=$(kcapi -x 1 -c "xts(aes)" -q $ct -k $key)
			}
			else
			{	
				dec_data=$(kcapi -x 1 -c "xts(aes)" -q $ct -k $key -i $iv)
			}
			fi
		
			if [ "$dec_data" != "$pt" ]
			then
			{
				echo -e "\nXTS Decryption failed for $file_name, vector count $i"
				
				echo "Exp PlainText : $pt"
				echo "Got PlainText : $dec_data"
				exit 1
				fail_count=$((fail_count+1))
			}
			else
			{
				pass_count=$((pass_count+1))
			}
			fi
		}
		fi
	}
	done
        echo "Total $test_str Decryption pass count = $pass_count, fail count = $fail_count"
	rm -rf /tmp/$enc_file /tmp/$vect_file /tmp/$dec_file
}
else
{
	echo "File not found"
}
fi
