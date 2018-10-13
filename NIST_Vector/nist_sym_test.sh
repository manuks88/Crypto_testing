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
	if echo $file_name | grep -iv ".rsp" > /dev/null || echo $file_name | grep -i "cfb" > /dev/null || echo $file_name | grep -i "ofb" || echo $file_name | grep -i "xts" > /dev/null
	then
	{
		exit 1
	}
	fi
	test_str=$(echo $file_name | awk -F '.rsp' '{print $1}' | awk -F '/' '{print $NF}')
	echo -e "\nRunning test vectors from $file_name"
        enc_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	sed -n '/ENCRYPT/,/DECRYPT/p' $file_name > /tmp/$enc_file
	vect_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)

	#CBC test
	if echo "$file_name" | grep -i cbc > /dev/null
	then
	{
		count=$(cat /tmp/$enc_file | grep -i "COUNT" | wc -l)
		for (( i=0;i<$count;i++ ))
		do
	        {
	                rm -rf /tmp/$vect_file
	                grep -w "COUNT = $i" /tmp/$enc_file -A 4 | sed 's/\s//g' > /tmp/$vect_file
	                key=$(grep 'KEY=' /tmp/$vect_file | cut -d=  -f2)
			iv=$(grep 'IV=' /tmp/$vect_file | cut -d=  -f2)
	                pt=$(grep 'PLAINTEXT=' /tmp/$vect_file | cut -d= -f2)
			ct=$(grep 'CIPHERTEXT=' /tmp/$vect_file | cut -d= -f2)
	
			if [ ! -z "$iv" ]
			then
			{
				enc_data=$(kcapi -x 1 -e -c "cbc(aes)" -p $pt -k $key -i $iv)
				dec_data=$(kcapi -x 1 -c "cbc(aes)" -q $ct -k $key -i $iv)
			}
			else
			{
				enc_data=$(kcapi -x 1 -e -c "cbc(aes)" -p $pt -k $key)
				dec_data=$(kcapi -x 1 -c "cbc(aes)" -q $ct -k $key)
			}
			fi

			if [ "$enc_data" != "$ct" ] || [ "$dec_data" != "$pt" ]
			then
			{
				echo -e "\nCBC test failed for $file_name, vector count $i"
				
				echo "Exp CipherText : $ct"
				echo "Got CipherText : $enc_data"

				echo -e "\nExp PlainText : $pt"
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
		done
		echo "Total $test_str pass count = $pass_count, fail count = $fail_count"
	}
	elif echo "$file_name" | grep -i ctr > /dev/null 
	then
	{
		count=$(cat /tmp/$enc_file | grep -i "COUNT" | wc -l)
		for (( i=0;i<$count;i++ ))
		do
	        {
	                rm -rf /tmp/$vect_file
	                grep -w "COUNT = $i" /tmp/$enc_file -A 4 | sed 's/\s//g' > /tmp/$vect_file
	                key=$(grep 'KEY=' /tmp/$vect_file | cut -d=  -f2)
			iv=$(grep 'IV=' /tmp/$vect_file | cut -d=  -f2)
	                pt=$(grep 'PLAINTEXT=' /tmp/$vect_file | cut -d= -f2)
			ct=$(grep 'CIPHERTEXT=' /tmp/$vect_file | cut -d= -f2)
	
			if [ ! -z "$iv" ]
			then
			{
				enc_data=$(kcapi -x 1 -e -c "ctr(aes)" -p $pt -k $key -i $iv)
				dec_data=$(kcapi -x 1 -c "ctr(aes)" -q $ct -k $key -i $iv)
			}
			else
			{
				enc_data=$(kcapi -x 1 -e -c "ctr(aes)" -p $pt -k $key)
				dec_data=$(kcapi -x 1 -c "ctr(aes)" -q $ct -k $key)
			}
			fi

			if [ "$enc_data" != "$ct" ] || [ "$dec_data" != "$pt" ]
			then
			{
				echo -e "\nCTR test failed for $file_name, vector count $i"
				
				echo "Exp CipherText : $ct"
				echo "Got CipherText : $enc_data"

				echo -e "\nExp PlainText : $pt"
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
		done
		echo "Total $test_str pass count = $pass_count, fail count = $fail_count"
	}
	elif echo "$file_name" | grep -i ecb > /dev/null
	then
	{
                count=$(cat /tmp/$enc_file | grep -i "COUNT" | wc -l)
                for (( i=0;i<$count;i++ ))
                do
                {       
                        rm -rf /tmp/$vect_file
                        grep -w "COUNT = $i" /tmp/$enc_file -A 3 | sed 's/\s//g' > /tmp/$vect_file
                        key=$(grep 'KEY=' /tmp/$vect_file | cut -d=  -f2)
                        pt=$(grep 'PLAINTEXT=' /tmp/$vect_file | cut -d= -f2)
                        ct=$(grep 'CIPHERTEXT=' /tmp/$vect_file | cut -d= -f2)
                        
                        enc_data=$(kcapi -x 1 -e -c "ecb(aes)" -p $pt -k $key)
                        dec_data=$(kcapi -x 1 -c "ecb(aes)" -q $ct -k $key)
                        
                        if [ "$enc_data" != "$ct" ] || [ "$dec_data" != "$pt" ]
                        then
                        {
                                echo -e "\nECB test failed for $file_name, vector count $i"
                                echo "Exp CT : $ct"
                                echo "Got CT : $enc_data"
                                echo "Exp PT : $pt"
                                echo "Got PT : $dec_data"
                                exit 1
                                fail_count=$((fail_count+1))
                        }
                        else
                        {
                                pass_count=$((pass_count+1))
                        }
                        fi
        
                }
                done
                echo "Total $test_str pass count = $pass_count, fail count = $fail_count"
	}
	fi
	rm -rf /tmp/$enc_file /tmp/$vect_file
}
else
{
	echo "File $file_name, not found"
}
fi
