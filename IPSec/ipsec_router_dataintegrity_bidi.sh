#!/bin/bash

#Change the following before starting test : 
#	1. debugfs path
#	2. interface to capture packets on 
#	3. sleep interval after starting test
#The machine where you run this script will be the Router machine.
# [DUT]---------------------------[....Router....]---------------------------[Peer]
#10.1.1.56			10.1.1.66	10.2.2.56		10.2.2.66


killall -g blast
rm -rf log_ipsec
rm -rf pcap_files
rm -rf ipsec.conf
mkdir log_ipsec
mkdir pcap_files
debugfs_path="/sys/kernel/debug/cxgb4/0000\:07\:00.4/"

if [ $# -ne 2 ]
then
{
	echo -e "Enter the DUT corporate and Peer corporate IP address."
	exit 1
}
fi

DUT_corp=$1
peer_corp=$2
ssh $DUT_corp "killall -g blast"
ssh $peer_corp "killall -g blast"

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
          'esp=aes128-sha512!' 'esp=aes192-sha512!' 'esp=aes256-sha512!' \
	  'esp=aes128ctr!' 'esp=aes192ctr!' 'esp=aes256ctr!' )
#all_algo=('esp=aes128ccm64!' 'esp=aes192ccm64!' 'esp=aes256ccm64!')
#all_algo=('esp=aes128gcm64!' 'esp=aes192gcm64!' 'esp=aes256gcm64!' \
#          'esp=aes128gcm96!' 'esp=aes192gcm96!' 'esp=aes256gcm96!' \
#          'esp=aes128gcm128!' 'esp=aes192gcm128!' 'esp=aes256gcm128!' )
#all_algo=('ah=sha1!' 'ah=sha256!' 'ah=sha384!' 'ah=sha512!' 'ah=sha256_96' \
#	  'esp=aes128-sha1!' 'esp=aes192-sha1!' 'esp=aes256-sha1!' \
#	  'esp=aes128-sha256!' 'esp=aes192-sha256!' 'esp=aes256-sha256!' \
#          'esp=aes128-sha384!' 'esp=aes192-sha384!' 'esp=aes256-sha384!' \
#          'esp=aes128-sha512!' 'esp=aes192-sha512!' 'esp=aes256-sha512!')

function test
{
	ibq_initial=`cat $debugfs_path/ibq* | grep ": 6d" | awk -F ' ' '{print $4}'`
	tcpdump -i enp7s0f4d1 -c 10 -w pcap_files/$2.pcap $3 &
	ssh $1 "cd /root/scripts/; rm -rf BSB_*"
	ssh $6 "cd /root/scripts/; rm -rf BSB_*"
	ssh $1 "cd /root/scripts/; sh blast_server.sh $4 55"
	ssh $6 "cd /root/scripts/; sh blast_client.sh $4 55"
	ssh $6 "cd /root/scripts/; sh blast_server.sh $5 55"
	ssh $1 "cd /root/scripts/; sh blast_client.sh $5 55"
	sleep 75
	ibq_cur=`cat $debugfs_path/ibq* | grep ": 6d" | awk -F ' ' '{print $4}'`
#	USE TIMESTOP FOR BLAST TEST ON BOTH SERVER and CLIENT, but using this as insurance :)
        tool_count_DUT=`ssh $1 "ps -ef|grep -i blast|wc -l"`
        tool_count_peer=`ssh $6 "ps -ef|grep -i blast|wc -l"`
        if [ $tool_count_DUT -ne 1 || $tool_count_peer -ne 1 ]
        then
        {
                while :
                do
                {
                        tool_count_DUT=`ssh $1 "ps -ef|grep -i blast|wc -l"`
			tool_count_peer=`ssh $6 "ps -ef|grep -i blast|wc -l"`
                        if [ $tool_count_DUT -eq 1 && $tool_count_peer -eq 1 ]
                        then
                        {
                                break
                        }
                        fi
                        ssh $1 "killall -g blast"
                        ssh $6 "killall -g blast"
                        for i in `ps -ef|grep -i "./blast"|awk -F ' ' '{print $2}'`;do echo $i;kill -9 $i;done
			echo "Killing blast forcefully." >> log_ipsec/$2.log 
                }
                done
        }
	fi
	ssh $1 "cd /root/scripts/; cat BSB_*|grep -i \"data error\"" > /dev/null
	if [ $? -ne 1 ]
	then
	{
		echo -e "Data corruption on server for $2" | tee -a log_ipsec/$2.log
		exit 1
	}
	fi
	ssh $6 "cd /root/scripts/; cat BSB_*|grep -i \"data error\"" > /dev/null
        if [ $? -ne 1 ]
        then
        {
                echo -e "Data corruption on client for $2" | tee -a log_ipsec/$2.log
                exit 1
        }
        fi
	if [[ $ibq_cur == $ibq_initial ]]
	then
	{
		echo -e "$2 didn't use Hardware" >> log_ipsec/$2.log
		echo -e "ibq_initial : $ibq_initial\nibq_cur : $ibq_cur" >> log_ipsec/$2.log
	}
	fi
}

for algo in "${all_algo[@]}"
do
{
	port_local_blast=$(( $RANDOM  + $RANDOM ))
	port_remote_blast=$(( $RANDOM  + $RANDOM ))
	logname=`echo $algo|awk -F '=' '{print $2}'`
	tcpdump_search=`echo $algo|awk -F '=' '{print $1}'`
	echo "************** $algo **************" | tee -a log_ipsec/$logname.log
	sed "8a\ \t$algo" ipsec.conf_beagle1_router > ipsec.conf
	mv ipsec.conf /etc/
	sed "8a\ \t$algo" ipsec.conf_burn13_router > ipsec.conf
	scp ipsec.conf $DUT_corp:/etc/
	sleep 2

	ipsec restart >> log_ipsec/$logname.log
	ssh $DUT_corp "ipsec restart" >> log_ipsec/$logname.log
	sleep 2
	echo "######### Bring up Connection #########" >> log_ipsec/$logname.log
	ssh $DUT_corp "ipsec up beagle-burn" >> log_ipsec/$logname.log
	cat log_ipsec/$logname.log | grep -i "failed"
	if [ $? -eq 0 ]
	then
	{
		echo "IPsec did not succeed for $algo."
		exit 1
	}
	fi
	sleep 2
	echo "Starting test on ports: $port_remote_blast & $port_local_blast"
	test $DUT_corp $logname $tcpdump_search $port_remote_blast $port_local_blast $peer_corp
	
	pcount=`tcpdump -r pcap_files/$logname.pcap|wc -l`
	if [[ $pcount == "0" ]]
	then
	{
		echo -e "<<<<<<<<<<<<<<<<<<<< Missing headers in packet. >>>>>>>>>>>>>>>>>>>>>>>>>>" | tee -a log_ipsec/$logname.log
		ipsec down beagle-burn >> log_ipsec/$logname.log
		ssh $DUT_corp "ipsec stop" >> log_ipsec/$logname.log
		ipsec stop >> log_ipsec/$logname.log
	}
	fi
	echo "Kill stale Blast instances" >> tee -a log_ipsec/$logname.log
	killall -g blast
	ssh $DUT_corp "killall -g blast"
	echo "######### Bring Down Connection #########" >> log_ipsec/$logname.log
	ipsec down beagle-burn >> log_ipsec/$logname.log
	ssh $DUT_corp "ipsec stop" >> log_ipsec/$logname.log
	ipsec stop >> log_ipsec/$logname.log
	echo -e "************************** Done with $algo. **************************\n"  | tee -a log_ipsec/$logname.log
}
done
