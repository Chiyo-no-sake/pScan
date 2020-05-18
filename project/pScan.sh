#!/bin/bash

# variable settings
OUT_FILE="pasini_res_scan.txt"
REMOTE_IP="193.246.121.236"
REMOTE_DIR="202005_CONSEGNE_I2A"
USR="i2a"

# top scanned ports accordingly to nmap database
PORT_TCP_RANGE="1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000"
PORT_UDP_RANGE="7,9,13,17,19,21-23,37,42,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,192,199,389,407,427,443,445,464,497,500,514-515,517-518,520,593,623,626,631,664,683,800,989-990,996-999,1001,1008,1019,1021-1034,1036,1038-1039,1041,1043-1045,1049,1068,1419,1433-1434,1645-1646,1701,1718-1719,1782,1812-1813,1885,1900,2000,2002,2048-2049,2148,2222-2223,2967,3052,3130,3283,3389,3456,3659,3703,4000,4045,4444,4500,4672,5000-5001,5060,5093,5351,5353,5355,5500,5632,6000-6001,6346,7938,9200,9876,10000,10080,11487,16680,17185,19283,19682,20031,22986,27892,30718,31337,32768-32773,32815,33281,33354,34555,34861-34862,37444,39213,41524,44968,49152-49154,49156,49158-49159,49162-49163,49165-49166,49168,49171-49172,49179-49182,49184-49196,49199-49202,49205,49208-49211,58002,65024"

if [ $(whoami) != root ]; then
	echo "unable to run without root privileges"
	exit 1
fi

#usage check
if [ $# -ne 1 ]; then
	echo "usage: $0 <interface>"
	exit 1
fi

IFACE=$1

# requirements check ---------------------------------------------------------------------------------------------------
echo "Checking for requirements"

# python3
if python3 -c "print('test')" &>/dev/null; then
  echo "python3 ok"
else
  echo "Please install python3 to use this script"
  exit 1
fi

# net-tools
if ifconfig &>/dev/null; then
  echo "net-tools ok"
else
  echo "please install net-tools to allow ip recon"
  exit 1
fi

# pip
if python3 -m pip &>/dev/null; then
  echo "pip ok"
else
  echo "No pip found, please install python-pip to run script"
  exit 1
fi

# scapy
if "python3" -c "import scapy" &> "/dev/null"; then
	echo "Requirement scapy already satisfied"
else
  echo "Installing scapy"
	if python3 -m pip install "$(pwd)"/dependencies/scapy-2.4.3.tar.gz &> ./pip3.log; then
		echo "Installed dependency scapy"
	else
		echo "Scapy installation not successfull, for more info: ./pip3.log"
		exit 1
	fi
fi 

# scan start -----------------------------------------------------------------------------------------------------------
echo "scan started, please wait..."

this_ip=$(ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p')

IPS=$(python3 bin/ToRangeAddr.py "$this_ip")

echo "Scanning $IPS, ports: "
echo "TCP: $PORT_TCP_RANGE"
echo "UDP: $PORT_UDP_RANGE"

SECONDS=0

echo "scan started, this can take a while..."

if "python3" "./bin/pscan.py" -i $IFACE $IPS -t $PORT_TCP_RANGE -u $PORT_UDP_RANGE | tee $OUT_FILE; then
	echo "Scan completed"
else
	echo "Error scanning"
	exit 1
fi

duration=$SECONDS
echo "$(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed."


echo "Trying to transfer over SSH with rsa_key, if not configured, the server will ask for pass."
# use scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null for skip prompting known hosts
if scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./rsa_key $OUT_FILE $USR@$REMOTE_IP:$REMOTE_DIR; then
  echo "File sent."
else
  echo "Error sending results with rsa key"
  echo "Trying to send without key. Password insertion will be prompted"

  if scp $OUT_FILE $USR@$REMOTE_IP:$REMOTE_DIR; then
    echo "All Completed"
  else
    echo "Error sending results"
  fi
fi