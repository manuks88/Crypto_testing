#!/bin/bash
rm -rf $(pwd)/data_file.txt
for i in {1..10}
{
        size=$(( RANDOM % 512))
        if [ $size == "0" ]
        then
        {
                size="512"
        }
	fi
	for (( j=1;j<=$size;j++ ))
	{
	        printf %s {0..9} >> $(pwd)/data_file.txt
	        printf %s {a..z} >> $(pwd)/data_file.txt
	        printf %s {A..Z} >> $(pwd)/data_file.txt
	        echo -n '$!' >> $(pwd)/data_file.txt
	}
        printf "\n" >> $(pwd)/data_file.txt
#        echo $i
}
