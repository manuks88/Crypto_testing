#!/bin/bash
killall -g blast
rm -rf log_ipsec
rm -rf pcap_files
rm -rf ipsec.conf
mkdir log_ipsec
mkdir pcap_files
debugfs_path="/sys/kernel/debug/cxgb4/0000\:82\:00.4/"
client_corp=$1
client_chel=$2
ssh $client_corp "killall -g blast"

if [ $# -ne 2 ]
then
{
	echo -e "Enter the client corporate and client chelsio IP address."
	exit 1
}
fi

all_algo=('ah=sha1!' 'ah=sha256!' 'ah=sha384!' 'ah=sha512!' 'ah=sha256_96'
          'esp=aes128!' 'esp=aes192!' 'esp=aes256!' 'esp=aesxcbc' 'esp=aescmac' \
          'esp=aes128ccm64!' 'esp=aes192ccm64!' 'esp=aes256ccm64!' \
          'esp=aes128ccm96!' 'esp=aes192ccm96!' 'esp=aes256ccm96!' \
          'esp=aes128ccm128!' 'esp=aes192ccm128!' 'esp=aes256ccm128!' \
          'esp=aes128gcm64!' 'esp=aes192gcm64!' 'esp=aes256gcm64!' \
          'esp=aes128gcm96!' 'esp=aes192gcm96!' 'esp=aes256gcm96!' \
          'esp=aes128gcm128!' 'esp=aes192gcm128!' 'esp=aes256gcm128!' \
          'esp=aes128-sha1!' 'esp=aes192-sha1!' 'esp=aes256-sha1!' \
          'esp=aes128-sha256!' 'esp=aes192-sha256!' 'esp=aes256-sha256!' \
          'esp=aes128-sha384!' 'esp=aes192-sha384!' 'esp=aes256-sha384!' \
          'esp=aes128-sha512!' 'esp=aes192-sha512!' 'esp=aes256-sha512!')

function test
{
	ibq_initial=`cat $debugfs_path/ibq* | grep ": 6d" | awk -F ' ' '{print $4}'`
	tcpdump -i eth2 -c 10 -w pcap_files/$2.pcap &
	ssh $1 "cd /root/scripts/; sh blast_server.sh" > /dev/null
	cd /root/scripts/
	sh blast_client.sh > /dev/null
	sleep 320
	ibq_cur=`cat $debugfs_path/ibq* | grep ": 6d" | awk -F ' ' '{print $4}'`
	tool_count=`ps -ef|grep -i blast|wc -l`
	if [ $tool_count -ne 1 ]
	then
	{
		while :
		do
		{
			tool_count=`ps -ef|grep -i blast|wc -l`
			echo $tool_count
			if [ $tool_count -eq 1 ]
			then
			{
				break
			}
			fi
			sleep 40
			ssh $1 "killall -g blast"
			for i in `ps -ef|grep -i "./blast"|awk -F ' ' '{print $2}'`;do echo $i;kill -9 $i;done
		}
		done
	}
	fi
	echo "Still in function"
	ssh $1 "cd /root/scripts/; cat BSB_*|grep -i \"data error\"" > /dev/null
	if [ $? -ne 1 ]
	then
	{
		echo -e "Data corruption on server for $2" | tee -a log_ipsec/$2.log
		exit 1
	}
	fi
	cat BSB_*|grep -i "data error" > /dev/null
        if [ $? -ne 1 ]
        then
        {
                echo -e "Data corruption on client for $2" | tee -a log_ipsec/$2.log
                exit 1
        }
        fi
	cd -
	if [[ $ibq_cur == $ibq_initial ]]
	then
	{
		echo -e "$2 didn't use Hardware" >> log_ipsec/$2.log
	}
	fi
}

for algo in "${all_algo[@]}"
do
{
	logname=`echo $algo|awk -F '=' '{print $2}'`
	tcpdump_search=`echo $algo|awk -F '=' '{print $1}'`
	echo "************** $algo **************" | tee -a log_ipsec/$logname.log
	sed "8a\ \t$algo" ipsec.conf_beagle1 > ipsec.conf
	mv ipsec.conf /etc/
	sed "8a\ \t$algo" ipsec.conf_burn13 > ipsec.conf
	scp ipsec.conf $client_corp:/etc/
	sleep 2

	ipsec restart >> log_ipsec/$logname.log
	ssh $client_corp "ipsec restart" >> log_ipsec/$logname.log
	sleep 2
	echo "######### Bring up Connection #########" >> log_ipsec/$logname.log
	ipsec up beagle-burn >> log_ipsec/$logname.log
	cat log_ipsec/$logname.log | grep -i "failed"
	if [ $? -eq 0 ]
	then
	{
		echo "IPsec did not succeed for $algo."
		exit 1
	}
	fi
	sleep 2

	test $client_chel $logname
	
	pcount=`tcpdump -r pcap_files/$logname.pcap $tcpdump_search |wc -l`
	if [[ $pcount == "0" ]]
	then
	{
		echo -e "<<<<<<<<<<<<<<<<<<<< Missing headers. >>>>>>>>>>>>>>>>>>>>>>>>>>" | tee -a log_ipsec/$logname.log
		ipsec down beagle-burn >> log_ipsec/$logname.log
		ssh $client_corp "ipsec stop" >> log_ipsec/$logname.log
		ipsec stop >> log_ipsec/$logname.log
	}
	fi

	echo "######### Bring Down Connection #########" >> log_ipsec/$logname.log
	ipsec down beagle-burn >> log_ipsec/$logname.log
	ssh $client_corp "ipsec stop" >> log_ipsec/$logname.log
	ipsec stop >> log_ipsec/$logname.log
	echo -e "************************** Done with $algo. **************************\n"  | tee -a log_ipsec/$logname.log
}
done
