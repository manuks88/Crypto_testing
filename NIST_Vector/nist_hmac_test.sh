#!/bin/bash

if [ $# -lt 1 ]
then
{
        echo "Provide file name."
        exit 1
}
fi

file_name=$1

if [ -f $file_name ]
then
{
	declare -a sha_algo=("20" "28" "32" "48" "64")
	for i in {0..4}
	do
	{
		fail_count=0
		pass_count=0
		arr_start=$i
	        arr_end=$((i+1))
		starting=${sha_algo[$arr_start]}
		ending=${sha_algo[$arr_end]}
		
		case $starting in
		'20')	algo="hmac(sha1)"
			;;
		'28')	algo="hmac(sha224)"
			;;
		'32')	algo="hmac(sha256)"
			;;
		'48')	algo="hmac(sha384)"
			;;
		'64')	algo="hmac(sha512)"
			;;
		esac

		rand_file1=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
		sed -n "/\[L\=$starting\]/,/\[L\=$ending\]/p" $file_name > /tmp/$rand_file1
		
		vect_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)

		count=$(cat /tmp/$rand_file1 | grep -i "count" | wc -l)
		for (( j=0;j<$count;j++ ))
		do
		{
			rm -rf /tmp/$vect_file
			grep -w "Count = $j" /tmp/$rand_file1 -A 5 | sed 's/\s//g' > /tmp/$vect_file
			Klen=$(grep 'Klen=' /tmp/$vect_file | cut -d=  -f2)
			Tlen=$(grep 'Tlen=' /tmp/$vect_file | cut -d=  -f2)
			Key=$(grep 'Key=' /tmp/$vect_file | cut -d=  -f2)
			Msg=$(grep 'Msg=' /tmp/$vect_file | cut -d=  -f2)
			Mac=$(grep 'Mac=' /tmp/$vect_file | cut -d=  -f2)

			mac_len=$((Tlen*2))
			hmac_exec=$(kcapi -x 3 -c "$algo" -p $Msg -k $Key)
			act_mac=$(echo $hmac_exec | head -c $mac_len)

			if [ "$act_mac" != "$Mac" ]
			then
			{
				echo -e "Test failed for $algo, from file $file_name, count=$j"
				echo "Exp Mac : $Mac"
				echo "Got Mac : $act_mac"
				fail_count=$((fail_count+1))
			}
			else
			{
				pass_count=$((pass_count+1))
			}
			fi
		}
		done
		echo "Total $algo pass count = $pass_count, fail count = $fail_count"
		rm -rf /tmp/$vect_file /tmp/$rand_file1
	}
	done
}
else
{
	echo -e "File $file_name not found"
	exit 1
}
fi
