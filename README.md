# xdp-filter-py
Filter packets using xdp eBPF

# Installation
Please follow [bcc install](https://github.com/iovisor/bcc/blob/master/INSTALL.md) step 

# Demo
```bash
> python3 xdp_filter.py -h
usage: xdp_filter.py [-h] --device DEVICE [--mode MODE] [--port PORT] [--ip IP] [--jitter JITTER]

Filter incoming packets on XDP layer.

optional arguments:
  -h, --help            show this help message and exit
  --device DEVICE, -d DEVICE
                        device
  --mode MODE, -m MODE  skb or driver mode.
  --port PORT, -p PORT  drop packets from certain port.
  --ip IP, -i IP        drop packets from certain ip.
  --jitter JITTER, -j JITTER
                        randomly drop packets. ( range: 0 ~ 100 )


> python3 xdp_filter.py -d ens5 -p 6379 # Drop all traffic to 6379 port

=== Printing drops with IP, hit CTRL+C to stop ===
10.20.14.216: 1
10.20.14.216: 2
10.20.14.216: 3
10.20.14.216: 4
10.20.14.216: 4
....
```
