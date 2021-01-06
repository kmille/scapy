#!/usr/bin/env python3
from scapy.all import *


def parse(p):
    print(p.summary())

sniff(offline="/tmp/dump.pcap", prn=parse, store=False)

