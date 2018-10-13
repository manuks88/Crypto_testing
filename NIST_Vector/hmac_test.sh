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
	if echo $file_name | grep -i monte > /dev/null || echo $file_name | grep -iv ".rsp" > /dev/null
	then
	{
#		echo "Not supporting this file, $file_name."
		exit 1
	}
	fi
	algo_name=$(echo $file_name | grep -o 'sha.*'|awk -F '_' '{print $1}'| awk '{print tolower($0)}')
	if [ "$algo_name" == "sha512_224" ] || [ "$algo_name" == "sha512_256" ]
	then
	{
		echo -e "\n$algo_name is an unsupported algo for kcapi, exiting...\n"
		exit 1
	}
	fi
	echo -e "\nRunning test for algo : $algo_name\nVectors from $file_name"
        rand_file1=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	cp $file_name /tmp/$rand_file1
	vect_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	count=$(cat /tmp/$rand_file1 | grep -i "COUNT" | wc -l)
	for (( i=0;i<$count;i++ ))
        {
                rm -rf /tmp/$vect_file
                grep -w "COUNT=$i" /tmp/$rand_file1 -A 4  > /tmp/$vect_file
                msg=$(grep 'Msg=' /tmp/$vect_file | cut -d=  -f2)
		msg_len=$(grep 'Msg_len=' /tmp/$vect_file | cut -d=  -f2)
                md=$(grep 'MD=' /tmp/$vect_file | cut -d= -f2)
		key=$(grep 'Key=' /tmp/$vect_file | cut -d= -f2)

		if [ "$msg" == "00" ]
		then
		{
			msg_dgst=$(kcapi -x 3 -c "hmac($algo_name)" -p "" -k $key)
		}
		else
		{
			msg_dgst=$(kcapi -x 3 -c "hmac($algo_name)" -p $msg -k $key)
		}
		fi
		if [ "$msg_dgst" != "$md" ]
		then
		{
			echo -e "\nTest failed for vector count $i"
			echo "Exp : $md"
			echo "Got : $msg_dgst"
			fail_count=$((fail_count+1))
		}
		else
		{
			pass_count=$((pass_count+1))
		}
		fi

        }
	echo "Total hmac($algo_name) pass count = $pass_count, fail count = $fail_count"
	
	rm -rf /tmp/$rand_file1 /tmp/$rand_file1 /tmp/$vect_file
}
else
{
	echo "File not found"
}
fi
