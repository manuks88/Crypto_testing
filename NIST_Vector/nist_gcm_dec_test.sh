#!/bin/bash
#kcapi will not work if IV is lesser or greater than 96 bits.

if [ $# -lt 1 ]
then
{
	echo "Provide file name."
	exit 1
}
fi

file_name=$1
pass_count=0
fail_count=0
ebad_count=0

if [ -f $file_name ]
then
{
	echo -e "\nRunning test vectors from $file_name"
	test_str=$(echo $file_name | awk -F '.rsp' '{print $1}' | awk -F '/' '{print $NF}') 
	rand_file1=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	sed -n '/\[IVlen \= 96\]/,/\[IVlen \= 8\]/p' $file_name > /tmp/$rand_file1	
	rand_file2=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	sed -e '/#/d' -e '/\[Keylen/d' -e '/\[IVlen/d' -e '/\[PTlen/d' -e '/\[AADlen/d' -e '/\[Taglen/d' /tmp/$rand_file1 > /tmp/$rand_file2
	rand_file3=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	awk 'BEGIN {c=0}/Count/{ gsub(/Count.*$/,"Count = "c) ; c++;print ; next}{print}' /tmp/$rand_file2 > /tmp/$rand_file3

	vect_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)

	count=$(cat /tmp/$rand_file1 | grep -i Count | wc -l)
	echo "Total num of tests : $count"
	for (( i=0;i<$count;i++ ))
	{
		grep -w "Count = $i" /tmp/$rand_file3 -A 6 | sed 's/\s//g' > /tmp/$vect_file
		key=$(grep 'Key=' /tmp/$vect_file | cut -d=  -f2)
		iv=$(grep 'IV=' /tmp/$vect_file | cut -d= -f2)
		aad=$(grep 'AAD=' /tmp/$vect_file | cut -d= -f2)
		tag=$(grep 'Tag=' /tmp/$vect_file | cut -d= -f2)
		plain=$(grep 'PT=' /tmp/$vect_file | cut -d= -f2)
		cipher=$(grep 'CT=' /tmp/$vect_file | cut -d= -f2)
		ebad=$(grep 'FAIL' /tmp/$vect_file)

		iv_len=$(echo -n $iv | wc -m)
		key_len=$(echo -n $key | wc -m)
		aad_len=$(echo -n $aad | wc -m)
		tag_len=$(echo -n $tag | wc -m)
		plain_len=$(echo -n $plain | wc -m)
		cipher_len=$(echo -n $cipher | wc -m)

#		if [ "$iv_len" != "2" ] && [ "$iv_len" != "256" ]
#		then
		dec_cmd="kcapi -x 2 -c \"gcm(aes)\" -k $key"
		if [ ! -z "$cipher" ]
		then
		{
			dec_cmd+=" -q $cipher"
		}
		fi
		if [ ! -z "$iv" ]
		then
		{
			dec_cmd+=" -i $iv"
		}
		fi
		if [ ! -z "$tag" ]
		then
		{
			dec_cmd+=" -t $tag"
		}
		fi
		if [ ! -z "$aad" ]
		then
		{
			dec_cmd+=" -a $aad"
		}
		fi
		exec_cmd=$(eval $dec_cmd)
	
		if [ -z "$cipher" ]
		then
		{
			if [ ! -z "$exec_cmd" ] 
			then
			{
				if echo "$exec_cmd" | grep "EBADMSG" > /dev/null || echo "$exec_cmd" | grep -i "fail" > /dev/null
				then
				{
					if [ ! -z "$ebad" ]
					then
					{
						ebad_count=$((ebad_count+1))
					}
					else
					{
						echo -e "\nGCM Dec test failed, reason unknown, count : $i"
						fail_count=$((fail_count+1))
					}
					fi
				}
				fi
			}
			else
			{
				pass_count=$((pass_count+1))
			}
			fi
		}
		else
		{
		        if [ ! -z "$exec_cmd" ]
		        then
			{
		                if echo "$exec_cmd" | grep "EBADMSG" > /dev/null || echo "$exec_cmd" | grep -i "fail" > /dev/null
		                then    
		                {
		                        if [ ! -z "$ebad" ]
		                        then    
		                        {       
		                                ebad_count=$((ebad_count+1))
		                        }
		                        fi
				}
	                        elif [ "$exec_cmd" != "$plain" ]
	                        then
	                        {       
	                                echo -e "\nGCM Dec test failed for $file_name, count : $i"
	                                echo "Exp PlainText : $plain"
	                                echo "Got PlainText : $exec_cmd"
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
		fi
	}
	echo "Total $test_str pass count = $pass_count, fail count = $fail_count, ebad_count = $ebad_count"
	rm -rf /tmp/$rand_file1 /tmp/$vect_file /tmp/$rand_file2 /tmp/$rand_file3
}
else
{
	echo "File not found"
}
fi
