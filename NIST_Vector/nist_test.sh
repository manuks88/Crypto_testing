#!/bin/bash

WORKSPACE="/mnt/workspace"
FUNHOSTD="$WORKSPACE/fungible-host-drivers"
FUNDRIVER="$WORKSPACE/fungible-host-drivers/linux/kernel"
FUNSDK="$WORKSPACE/FunSDK"

repo_update()
{
	echo "Updating Fun Driver..."
	cd $FUNHOSTD
	git reset
	git checkout .
	git clean -fdx	
	git checkout master
	git pull origin master
	echo "Updating FunSDK..."
	cd $FUNSDK
        git reset
        git checkout .
        git clean -fdx  
        git checkout master
        git pull origin master
}

build_driver()
{
	echo "Build FunSDK..."
	cd $FUNSDK
	./scripts/bob --sdkup
	echo "Build Funcrypto driver..."
	cd $FUNDRIVER
	make uninstall
	make clean
	make distclean
	make PALLADIUM=yes
}

export WORKSPACE

if lspci | grep -i "1dad" 
then
{
	repo_update
	build_driver

	echo "Load funcrypto..."
	sudo insmod ${FUNDRIVER}/funcrypto.ko
	sleep 2
        sudo modprobe modprobe algif_aead
        sudo modprobe algif_rng
        sudo modprobe algif_hash
        sudo modprobe algif_skcipher	
	echo "List loaded modules..."
	sudo lsmod | grep -i fun
	sleep 5

	if cat /proc/crypto | grep -i funcrypto > /dev/null
	then
	{
		for iter in {1..1}
		do
		{
#			for i in /test_vectors/shabytetestvectors/*
#			do
#				/test_vectors/nist_sha_test.sh $i 
#			done
			for j in /test_vectors/sym_cipher/cust_sym/*
			do
				/test_vectors/nist_sym_test.sh $j 
			done
	
#	#		/test_vectors/nist_gcm_test.sh /test_vectors/aead_cipher/gcmtestvectors/gcmEncryptExtIV128.rsp
#	
#			for k in /test_vectors/sym_cipher/XTS*
#			do
#				/test_vectors/nist_xts_test.sh $k 
#			done
#	
#			for l in /test_vectors/hmacvectors/*
#			do
#				/test_vectors/hmac_test.sh $l 
#			done
#			for m in /test_vectors/shabytetestvectors/64K/*
#			do
#				/test_vectors/nist_sha_test.sh $m
#			done
			echo -e "\n********** Test iteration $iter **********"
		}
		done

		echo "Interrupt stats..."
		cat /proc/interrupts |grep -i fu

		sudo rmmod funcrypto
	
		exit    0
	}
	else
	{
		echo "Error : Funcrypto not loaded."
		exit 1
	}
	fi
}
else
{
	echo "FAIL"
	exit 1
}
fi
