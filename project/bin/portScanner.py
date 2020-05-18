#!python3

import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

import time
import random

TCP_SYN_ACK = 0x12
TCP_RST_ACK = 0x14


def arp_scan(net_addr: str, interface: str):
    """ perform an arp scan on given interface and ip address list

    :param net_addr: string format for ip address like '192.168.1-10.0-255
    :param interface: string to identify network interface to use
    :return: a list of dict like [ {'IP':192.xx.xx.x, 'MAC':fa:12:4d:12:xx:xx}, { ... } ]
    """

    addr_list = get_ip_list(net_addr)
    results = []

    for ip in addr_list:
        # constructing the packet: layer2 broadcast / arp request with ip
        packt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

        # send packets and getting list of packets received and sents
        answ, unansw = srp(packt, interface, timeout=0.1, verbose=False)

        for sent, recv in answ:
            if recv:
                ip = recv[ARP].psrc
                mac = recv[Ether].src
                results.append({'IP': ip, 'MAC': mac})

    return results


def tcp_syn_scan(ip_addr: str, interface: str, ports: str = "0-1023"):
    """ perform a TCP synchronize scan on the given ip, ports and interface

    :param ip_addr: string containing the IP of the target host
    :param interface: string to identify network interface to use
    :param ports: list of ports to scan
    :return: a list of open ports for the given host
    """
    open_ports = []

    ports = get_port_list(ports)

    # soft measures to avoid low level ids
    random.shuffle(ports)

    for port in ports:
        # create a tcp syn packet to sent to ip_addr
        packt = IP(dst=ip_addr) / TCP(dport=port, flags='S')
        # send and get response
        ans = sr1(packt, interface, timeout=0.1, verbose=False)
        if ans and ans.haslayer(TCP) and ans.getlayer(TCP).flags == TCP_SYN_ACK:
            open_ports.append(port)
            sr1(IP(dst=ip_addr) / TCP(dport=ans.sport, flags='R'), verbose=False, timeout=0.1)

    return open_ports


def udp_scan(ip_addr: str, interface: str, ports: str = "0-1023"):
    """ perform UDP scan over target IP, interface and ports. can be really slow

    :param ip_addr: string containing the IP of the target host
    :param interface: string to identify network interface to use
    :param ports: list of ports to scan
    :return: a dict with 3 entryes: OPEN, FILTERED, OPEN|FILTERED, containing a list of port for each state
    """
    res_ports = {"OPEN": [], "FILTERED": [], "OPEN|FILTERED": []}

    ports = get_port_list(ports)

    random.shuffle(ports)

    for port in ports:
        res = udp_scan_port(ip_addr, interface, port)
        if res == "Open":
            res_ports.get("OPEN").append(port)
        elif res == "Filtered":
            res_ports.get("FILTERED").append(port)
        elif res == "Open|Filtered":
            res_ports.get("OPEN|FILTERED").append(port)

    return res_ports


def udp_scan_port(dst_ip: str, iface: str, dst_port: str):
    """ scan a specific single UDP port on given interface and ip

    :param dst_ip: string containing the IP of the target host
    :param iface: string to identify network interface to use
    :param dst_port: the UDP port targeted by the scan
    :return: string representing status of the port, '?' if not known
    """

    ans = sr1(IP(dst=dst_ip) / UDP(dport=dst_port), iface, timeout=0.3, verbose=False)
    if ans is None:
        retrans = []
        for count in range(0, 3):
            retrans.append(sr1(IP(dst=dst_ip) / UDP(dport=dst_port), iface, timeout=0.3, verbose=False))
        for item in retrans:
            if item is not None:
                ans = item

    if ans is None:
        return "Open|Filtered"
    if ans is not None and ans.haslayer(UDP):
        return "Open"
    elif ans is not None and ans.haslayer(ICMP):
        if int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) == 3:
            return "Closed"
        elif (int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 9, 10,
                                                                                     13]):
            return "Filtered"
    else:
        return "?"


def get_port_list(port_range: str):
    """ produces a list of ports given a formatted string

    :param port_range: a string like '100-120,200,201' to specify port and ranges
    :return: the computed full list of ports specified by port_range
    """

    ranges = port_range.split(',')
    ports = []
    for ran in ranges:
        limit = ran.split('-')
        for i in range(int(limit[0]), int(limit[len(limit) - 1]) + 1):
            ports.append(i)
    return ports


def get_ip_list(ipaddr: str):
    """ produces a list of ip given the ip range in a formatted string

    :param ipaddr: a string formatted like '192.168.1-20.0-255' specifying the range of ips
    :return: a full list containing each ip produced from the ipaddr string
    """

    ip_list = []
    ip_bytes = ipaddr.split('.')

    # start creating first byte alternatives
    range_b = ip_bytes[0].split('-')

    if len(range_b) == 2:
        range_b = range(int(range_b[0]), int(range_b[1]) + 1)

    for i in range_b:
        ip1 = str(i)

        # start analyzing second byte
        range_b2 = ip_bytes[1].split('-')

        if len(range_b2) == 2:
            range_b2 = range(int(range_b2[0]), int(range_b2[1]) + 1)

        for i2 in range_b2:
            ip2 = ip1 + "." + str(i2)
            # start analyzing third byte
            range_b3 = ip_bytes[2].split('-')

            if len(range_b3) == 2:
                range_b3 = range(int(range_b3[0]), int(range_b3[1]) + 1)

            for i3 in range_b3:
                ip3 = ip2 + "." + str(i3)

                range_b4 = ip_bytes[3].split('-')

                if len(range_b4) == 2:
                    range_b4 = range(int(range_b4[0]), int(range_b4[1]) + 1)

                for i4 in range_b4:
                    ip4 = ip3 + "." + str(i4)
                    ip_list.append(ip4)

    return ip_list
