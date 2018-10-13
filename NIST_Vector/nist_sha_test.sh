#!/bin/bash
#Works for sha1, sha2 & sha3

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
	algo_name=$(echo $file_name | grep -o 'SHA.*'| sed 's/ShortMsg.rsp//g' | sed 's/LongMsg.rsp//g' | sed 's/Varsize.rsp//g' | awk '{print tolower($0)}')
	#Not using below as some files don't following that pattern match ie., in LongMsg.rsp
	#algo_name=$(cat $file_name | grep -i "^#"|grep -i tests|awk -F 'tests' '{print $1}'|tr -d '#-/ '|awk '{print tolower($0)}')
	echo -e "\nRunning test for algo : $algo_name\nvectors from $file_name"
        rand_file1=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
        sed -n '/\[L/,//p' $file_name > /tmp/$rand_file1
        rand_file2=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
        sed -e '/\[L/d' /tmp/$rand_file1 > /tmp/$rand_file2
	vect_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	count=$(cat /tmp/$rand_file2 |sed -n -e 's/^.*Len = //p')
	if echo $algo_name | grep -i "sha3_" > /dev/null
	then
	{
		if lspci | grep -i "1dad"
		then
		{
		algo_name=$(echo $algo_name | tr '_' '-')
		for i in $count
	        {
	                rm -rf /tmp/$vect_file
	                grep -w "Len = $i" /tmp/$rand_file2 -A 3 | sed 's/\s//g' > /tmp/$vect_file
	                msg=$(grep 'Msg=' /tmp/$vect_file | cut -d=  -f2)
			msg_len=$(echo -n $msg | wc -m)
	                md=$(grep 'MD=' /tmp/$vect_file | cut -d= -f2)
	
			if [ "$msg" == "00" ]
			then
			{
				msg_dgst=$(kcapi -x 3 -c "$algo_name" -p "")
			}
			else
			{
				msg_dgst=$(kcapi -x 3 -c "$algo_name" -p $msg)
			}
			fi
			if [ "$msg_dgst" != "$md" ]
			then
			{
				echo -e "\nTest failed for $algo_name, $file_name, vector count $i"
				echo "Exp : $md"
				echo "Got : $msg_dgst"
				exit 1
				fail_count=$((fail_count+1))
			}
			else
			{
				pass_count=$((pass_count+1))
			}
			fi
	
	        }
		}
		else
		{
			echo "Not running SHA3 tests are fungible device is not there."
		}
		fi
	}
	else
	{
		for i in $count
	        {
	                rm -rf /tmp/$vect_file
	                grep -w "Len = $i" /tmp/$rand_file2 -A 3 | sed 's/\s//g' > /tmp/$vect_file
	                msg=$(grep 'Msg=' /tmp/$vect_file | cut -d=  -f2)
			msg_len=$(echo -n $msg | wc -m)
	                md=$(grep 'MD=' /tmp/$vect_file | cut -d= -f2)
	
			if [ "$msg" == "00" ]
			then
			{
				msg_dgst=$(kcapi -x 3 -c "$algo_name" -p "")
			}
			else
			{
				msg_dgst=$(kcapi -x 3 -c "$algo_name" -p $msg)
			}
			fi
			if [ "$msg_dgst" != "$md" ]
			then
			{
				echo -e "\nTest failed for $algo_name, $file_name, vector count $i"
				echo "Exp : $md"
				echo "Got : $msg_dgst"
				exit 1
				fail_count=$((fail_count+1))
			}
			else
			{
				pass_count=$((pass_count+1))
			}
			fi
	
	        }
	}
	fi
	echo "Total $algo_name Pass_Count = $pass_count, Fail_Count = $fail_count"
	
	rm -rf /tmp/$rand_file1 /tmp/$rand_file2 /tmp/$vect_file /tmp/res
}
else
{
	echo "File not found"
}
fi
