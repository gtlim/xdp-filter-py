# xdp-filter-py
Filter packets using xdp eBPF

# Installation
Please follow bcc install step described in https://github.com/iovisor/bcc/blob/master/INSTALL.md

# Demo
```bash
> python3 xdp_filter.py -d ens5 -p 6379 # Drop all traffic to 6379 port

> === Printing drops with IP, hit CTRL+C to stop ===
10.20.14.216: 1
10.20.14.216: 2
10.20.14.216: 3
10.20.14.216: 4
10.20.14.216: 4
....
```
