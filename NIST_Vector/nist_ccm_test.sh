#!/bin/bash
#Use CCM vectors generated after merge on NIST rsp

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
buffer_count=0

if [ -f $file_name ]
then
{
	echo -e "\nRunning test vectors from $file_name"
	test_str=$(echo $file_name | awk -F '.rsp' '{print $1}' | awk -F '/' '{print $NF}')	
        rand_file1=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
	cp $file_name /tmp/$rand_file1

	vect_file=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)

	count=$(cat /tmp/$rand_file1 | grep -i Count | wc -l)
	for (( i=0;i<$count;i++ ))
	{
		grep -w "Count = $i" /tmp/$rand_file1 -A 8 | sed 's/\s//g' > /tmp/$vect_file
		key=$(grep 'Key=' /tmp/$vect_file | cut -d=  -f2)
		nonce=$(grep 'Nonce=' /tmp/$vect_file | cut -d= -f2)
		adata=$(grep 'Adata=' /tmp/$vect_file | cut -d= -f2)
		tag=$(grep 'Tag=' /tmp/$vect_file | cut -d= -f2)
		cipher=$(grep 'CT=' /tmp/$vect_file | cut -d= -f2)
		payload=$(grep 'Payload=' /tmp/$vect_file | cut -d= -f2)
		ebad=$(grep 'Result=' /tmp/$vect_file | cut -d= -f2)
		payload_len=$(grep 'PTlen=' /tmp/$vect_file | cut -d= -f2)

		iv_len=$(echo -n $iv | wc -m)
		key_len=$(echo -n $key | wc -m)
		adata_len=$(echo -n $adata | wc -m)
		cipher_len=$(echo -n $cipher | wc -m)

		if [ "$payload_len" == "0" ]
		then
		{
			ctag=$(echo -n $cipher)
			payload=""
			cipher=""
			payload_len="0"
			cipher_len="0"
		}
		else
		{
			tag_cut_len=$((tag*2))
			ctag=$(echo -n $cipher | tail -c $tag_cut_len)
			pt_cut_len=$((payload_len*2))
			cipher=$(echo -n $cipher | head -c $pt_cut_len)
		} 
		fi

		if [ "$adata" == "00" ]
		then
		{
			adata=""
		}
		fi

		if [ "$ebad" == "Fail" ]
		then
		{
			dec_cmd="kcapi -x 2 -c \"ccm(aes)\" -k $key -n $nonce"
			if [ ! -z "$cipher" ]
			then
			{
				dec_cmd+=" -q $cipher"
			}
			fi
			if [ ! -z "$adata" ]
			then
			{
				dec_cmd+=" -a $adata"
			}
			fi
			if [ ! -z "$ctag" ]
			then
			{
				dec_cmd+=" -t $ctag"
			}
			fi
			exec_cmd=$(eval $dec_cmd)

			if [ -z "$payload" ]
			then
			{
				if [ "EBADMSG" == "$exec_cmd" ]
				then
				{
					ebad_count=$((ebad_count+1))
				}
				elif echo $exec_cmd | grep -i "buffer failed" > /dev/null
				then
				{
					buffer_count=$((buffer_count+1))
				}
				elif echo $exec_cmd | grep -i "fail"
				then
				{
					echo -e "\nCCM Dec test failed for $fail_name, count : $i"
					fail_count=$((fail_count+1))
				}
				else
				{
					pass_count=$((pass_count+1))
				}
				fi
			}
			else
			{
				act_pt=$(echo -n $exec_cmd)
				if [ "$act_pt" != "$payload" ]
				then
				{
					echo -e "\nCCM Dec test failed for $file_name, count : $i"
					echo "Exp PlainText : $payload"
					echo "Got PlainText : $act_pt"
					fail_count=$((fail_count+1))
					exit 1
				}
				else
				{
					pass_count=$((pass_count+1))
				}
				fi
			}
			fi
		}
		else
		{
		        dec_cmd="kcapi -x 2 -c \"ccm(aes)\" -k $key -n $nonce"
                        if [ ! -z "$cipher" ]
                        then
                        {
                                dec_cmd+=" -q $cipher"
                        }
                        fi
                        if [ ! -z "$adata" ]
                        then
                        {
                                dec_cmd+=" -a $adata"
                        }
                        fi
                        if [ ! -z "$ctag" ]
                        then
                        {
                                dec_cmd+=" -t $ctag"
                        }
                        fi
                        exec_cmd=$(eval $dec_cmd)

			act_pt=$(echo -n $exec_cmd)
			if echo $exec_cmd | grep -i "buffer failed" > /dev/null
			then
			{
				buffer_count=$((buffer_count+1))
			}
			elif [ "$act_pt" != "$payload" ]
			then
			{
			        echo -e "\nCCM Dec test failed for $file_name, count : $i"
			        echo "Exp PlainText : $payload"
			        echo "Got PlainText : $act_pt"
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
	echo "Total count in $file_name, pass_count = $pass_count, fail_count = $fail_count, ebad_count=$ebad_count, buffer_count=$buffer_count"
	rm -rf /tmp/$rand_file1 /tmp/$vect_file
}
else
{
	echo "File not found"
}
fi
