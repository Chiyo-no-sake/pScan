#!python3
import sys
import portScanner


def usage(argv):
    print("Usage: ", argv[0], " -i <interface> <ip_range> -t [<port-range>] -u [<port-range>]")
    print("\t ip_range must be like: 192.168-169.178.1-255")
    print(
        "\t port-range must be expressed like 20-980, default range will be 0-1000, ranges can be separed by a comma:")
    print("\t\t ex. 20-900,1000-1010,3000-3010")
    print("\t -t TCP ports to scan")
    print("\t -u UDP ports to scan")
    sys.exit(1)


def main(argv):
    port_tcp_ranges = 0
    port_udp_ranges = 0
    iface = argv[2]
    ip_range = argv[3]

    if len(argv) == 8:
        port_tcp_ranges = argv[5]
        port_udp_ranges = argv[7]

    # starting ARP scan
    hosts = portScanner.arp_scan(ip_range, iface)

    for host in hosts:
        print(host['IP'], " ", host['MAC'])

        # start TCP SYN scan

        if port_tcp_ranges:
            open_tcp_ports = portScanner.tcp_syn_scan(host['IP'], iface, str(port_tcp_ranges))
        else:
            open_tcp_ports = portScanner.tcp_syn_scan(host['IP'], iface)

        if open_tcp_ports is not None:
            # print("list of opened ports for host", host)
            for port in open_tcp_ports:
                print("\tTCP:" + str(port))

        # start UDP scan
        if port_udp_ranges:
            udp_result = portScanner.udp_scan(host['IP'], iface, str(port_udp_ranges))
        else:
            udp_result = portScanner.udp_scan(host['IP'], iface)

        if udp_result is not None:
            for port in udp_result.get("OPEN"):
                print("\tUDP:" + str(port) + "-open")
            for port in udp_result.get("FILTERED"):
                print("\tUDP:" + str(port) + "-filtered")
            for port in udp_result.get("OPEN|FILTERED"):
                print("\tUDP:" + str(port) + "-open|filtered")


if __name__ == "__main__":
    try:
        if len(sys.argv) < 4:
            usage(sys.argv)

        main(sys.argv)

    except KeyboardInterrupt:
        print("CTRL-C detected, quitting")
        sys.exit(0)
