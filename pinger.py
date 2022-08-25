import sys
import ipaddress
from scapy.all import *


def main(hostname, count):

    # input validation
    try:
        validate_input(hostname, count)
    except ValueError as e:
        print(e)

def validate_input(hostname, count):
    try:
        count = int(count)
        if hostname.endswith('.com'):
            print("Received a domain name, going to make a DNS query for ", hostname)
            ip_addr = make_query(hostname)
            print('DNS query resulted in: ', ip_addr)
            send_icmp(ip_addr, count)
        elif ipaddress.ip_address(hostname):
            # in case of an ip address, try to validate the input
            print("Received a valid IP address.")
            send_icmp(hostname, count)
    except ValueError as e:
        print(e)


def make_query(hostname):
    # form request
    query = IP(dst="8.8.8.8") / UDP(sport=RandShort(), dport=53) / \
        DNS(rd=1, qd=DNSQR(qname=hostname))

    # make DNS query and retrieve IP addr from DNS answer
    answer = sr(query, verbose=0)
    result = answer[0][DNS][0].answer[DNS][DNSRR].rdata

    return result


def send_icmp(dst_addr, count):

    print("Trying to ping", dst_addr)

    # form an ICMP packet with dummy payload
    packet = IP(dst=dst_addr, ttl=10) / ICMP() / "XXXXXXXXXXX"

    # send icmp echo and wait for reply
    reply = srloop(packet, count=int(count))
    return


# The script/main function takes two arguments:
## first argument should be a valid IP address or a FQDN
## second argument should be an integer.')

if __name__ == "__main__":
    host = sys.argv[1]
    count = sys.argv[2]
    main(host, count)
