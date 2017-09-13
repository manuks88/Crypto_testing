#!/bin/bash
killall -g blast
killall -g iperf
rm -rf perf_log
rm -rf perf_result
rm -rf ipsec.conf
mkdir perf_log
mkdir perf_result
debugfs_path="/sys/kernel/debug/cxgb4/0000\:82\:00.4/"
client_corp=$1
client_chel=$2

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
	iperf -c $1 -P 8 -t 30 > perf_result/$2.log
	ibq_cur=`cat $debugfs_path/ibq* | grep ": 6d" | awk -F ' ' '{print $4}'`
	if [[ $ibq_cur == $ibq_initial ]]
	then
	{
		echo -e "$2 didn't use Hardware" >> perf_log/$2.log
	}
	fi
	BW=`cat perf_result/$2.log | grep -i sum| awk -F '  ' '{print $4}'`
	printf "Algo:$2\t\t:\tBW:$BW\n" >> perf_log/perf_summary.log
}

for algo in "${all_algo[@]}"
do
{
	logname=`echo $algo|awk -F '=' '{print $2}'`
	echo "************** $algo **************" | tee -a perf_log/$logname.log
	sed "8a\ \t$algo" ipsec.conf_beagle1 > ipsec.conf
	mv ipsec.conf /etc/
	sed "8a\ \t$algo" ipsec.conf_burn13 > ipsec.conf
	scp ipsec.conf $client_corp:/etc/
	sleep 2

	ipsec restart >> perf_log/$logname.log
	ssh $client_corp "ipsec restart" >> perf_log/$logname.log
	sleep 2
	echo "######### Bring up Connection #########" >> perf_log/$logname.log
	ipsec up beagle-burn >> perf_log/$logname.log
	cat perf_log/$logname.log | grep -i "failed"
	if [ $? -eq 0 ]
	then
	{
		echo "IPsec did not succeed for $algo."
		exit 1
	}
	fi
	sleep 2

	test $client_chel $logname
	
	echo "######### Bring Down Connection #########" >> perf_log/$logname.log
	ipsec down beagle-burn >> perf_log/$logname.log
	ssh $client_corp "ipsec stop" >> perf_log/$logname.log
	ipsec stop >> perf_log/$logname.log
	echo -e "************************** Done with $algo. **************************\n"  | tee -a perf_log/$logname.log
}
done
