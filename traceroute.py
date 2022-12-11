#!/usr/bin/env python3
import sys

import ipwhois
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.volatile import RandShort
from scapy.sendrecv import sr1
from scapy.config import conf
from scapy.supersocket import L3RawSocket

from arg_parser import get_parser
from validators import validate_args
from whois import Whois
from utils import is_ipv6


class Traceroute:
    def __init__(self, ip_address: str,
                 protocol: str,
                 timeout: float,
                 max_ttl: int,
                 verbose: bool,
                 port: int = None):
        self.ip_address = ip_address
        self.port = port
        self.protocol = protocol
        self.timeout = timeout
        self.max_ttl = max_ttl
        self.verbose = verbose
        conf.L3socket = L3RawSocket

    def __get_icmp_packet(self, ttl: int) -> ICMP:
        if is_ipv6(self.ip_address):
            return IPv6(dst=self.ip_address,
                        hlim=ttl) / ICMPv6EchoRequest()

        return IP(dst=self.ip_address,
                  ttl=ttl,
                  id=RandShort()) / ICMP()

    def __get_tcp_packet(self, ttl: int) -> TCP:
        if is_ipv6(self.ip_address):
            packet = IPv6(dst=self.ip_address,
                          hlim=ttl) / TCP()
        else:
            packet = IP(dst=self.ip_address,
                        ttl=ttl,
                        id=RandShort()) / TCP()

        if self.port:
            packet.dport = self.port

        return packet

    def __get_udp_packet(self, ttl: int) -> UDP:
        if is_ipv6(self.ip_address):
            packet = IPv6(dst=self.ip_address,
                          hlim=ttl) / UDP()
        else:
            packet = IP(dst=self.ip_address,
                        ttl=ttl,
                        id=RandShort()) / UDP()

        if self.port:
            packet.dport = self.port

        return packet

    def __get_packet_func(self) -> callable:
        if self.protocol == "icmp":
            return self.__get_icmp_packet
        elif self.protocol == "tcp":
            return self.__get_tcp_packet
        elif self.protocol == "udp":
            return self.__get_udp_packet

    def run(self):
        packet_func = self.__get_packet_func()
        ttl = 1
        while ttl <= self.max_ttl:
            packet = packet_func(ttl)
            answer = sr1(packet, timeout=self.timeout, verbose=0)
            if not answer:
                print(f"{ttl}\t*")
                ttl += 1
                continue
            time = (answer.time - packet.sent_time) * 1000
            print(f"{ttl}\t{answer.src:<15}\t{time:.3f} ms", end="\t")

            if self.verbose:
                try:
                    whois = Whois(answer.src)
                    print(whois.asn)
                except ipwhois.exceptions.IPDefinedError:
                    print()
            else:
                print()

            if answer.src == self.ip_address:
                break

            ttl += 1


def main():
    args = get_parser().parse_args()

    if error_code := validate_args(args.IP_ADDRESS, args.port, args.timeout):
        sys.exit(error_code)

    traceroute = Traceroute(args.IP_ADDRESS, args.PROTOCOL, args.timeout,
                            args.max_ttl, args.verbose, args.port)

    traceroute.run()


if __name__ == "__main__":
    main()
