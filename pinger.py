import sys
import ipaddress
from scapy.all import *

#hostname = "google.com"

def main(hostname, limit):

    # input validation
    #try:
    validate_input(hostname, limit)
    #except:
    #    raise ValueError('Non-existent or invalid input as first argument')

def validate_input(hostname, limit):
    try:
        if hostname.endswith('.com'):
            print("Received a domain name, going to make a DNS query for ", hostname)
            ip_addr = make_query(hostname)
            print('DNS query resulted in: ', ip_addr)
            send_icmp(ip_addr, limit)
        else:
            # in case of an ip address, try to validate the input
            ip_addr = ipaddress.ip_address(hostname)
            print("Received a valid IP address.")
            send_icmp(hostname, limit)
    except:
        ValueError("Invalid value in the first argument")


def make_query(hostname):
    # form request
    query = IP(dst="8.8.8.8") / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=hostname))

    # make DNS query
    answer = sr(query, verbose=0)
    result = answer.an.rdata

    return result


def send_icmp(dst_addr, limit):

    print ("Trying to ping", dst_addr)

    # form an ICMP packet with dummy payload
    packet = IP(dst=dst_addr, ttl=10) / ICMP() / "XXXXXXXXXXX"

    #send icmp echo and wait for reply
    reply = srloop(packet, count=int(limit))
    return


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
