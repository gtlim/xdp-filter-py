#!/usr/bin/python
from bcc import BPF
import time
import struct
import socket
import argparse

parser = argparse.ArgumentParser(description='Filter incoming packets on XDP layer.')
parser.add_argument('--device', '-d', dest='device', help='device', required=True)
parser.add_argument('--mode', '-m', dest='mode', help='skb or driver mode.', default='skb')
parser.add_argument('--port', '-p', dest='port', help='drop packets from certain port.')
parser.add_argument('--ip', '-i', dest='ip', help='drop packets from certain ip.')
parser.add_argument('--syn', '-s', dest='ip', help='drop packets with syn only.')
parser.add_argument('--jitter', '-j', dest='jitter', help='randomly drop packets. ( range: 0 ~ 100 )', default='100')

args = parser.parse_args()
offload_device = None
mode = BPF.XDP
flags = 0


if args.mode == 'skb':
    # XDP_FLAGS_SKB_MODE
    flags |= BPF.XDP_FLAGS_SKB_MODE
if args.mode == 'drv':
    # XDP_FLAGS_DRV_MODE
    flags |= BPF.XDP_FLAGS_DRV_MODE

filter_port = -1
filter_ip = -1
filter_syn_only = -1

if args.port:
    filter_port = args.port

if args.ip:
    adr = args.ip.split('.')
    adr.reverse()
    sadr = '.'.join(adr)
    # convert to binary
    filter_ip = struct.unpack("!L", socket.inet_aton(sadr))[0]

if args.syn:
    filter_syn_only = 1

cflags = ["-w", "-DPORTNUM=%s" % filter_port, "-DIP=%s" % filter_ip, "-DJITTER=%s" % args.jitter,
          "-DSYN=%s" % filter_syn_only]

text_file = open("./xdp_filter.c", "r")
data = text_file.read()
text_file.close()
b = BPF(text=data, cflags=cflags, device=offload_device)
fn = b.load_func("xdp_main", mode, offload_device)
b.attach_xdp(args.device, fn, flags)
counter = b.get_table("counter")
print("=== Printing drops with IP, hit CTRL+C to stop ===")
while 1:
    try:
        for k, v in counter.items():  # type(k) = c_uint, type(v) = c_long
            address = socket.inet_ntoa(struct.pack('!L', k.value))
            adr = address.split('.')
            adr.reverse()
            sadr = '.'.join(adr)
            print("{}: {}".format(sadr, v.value))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break
b.remove_xdp(args.device, flags)
