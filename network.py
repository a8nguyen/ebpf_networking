import socket
import os
from pyroute2 import IPRoute
from bcc import BPF

interface = "eth0"
#load bpf program
b = BPF(src_file="./network.c")
b.attach_kprobe(event="tcp_v4_connect",fn_name="tcpconnect")

#set up socket filter
f = b.load_func("socket_filter", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(f, interface)
fd = f.sock
sock = socket.fromfd(fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
sock.setblocking(True)

#interface with XDP
fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx,0)

# use congestion control (dumb example for ping)
# always drop packet

ipr = IPRoute()
fi = b.load_func("tc", BPF.SCHED_CLS)
links = ipr.link_lookup(ifname=interface)
idx = links[0]

try:
    ipr.tc("add", "ingress", idx, "ffff:")
except:
    print("qdisc ingress already exists")
ipr.tc("add-filter", 'bpf', idx, ":1", fd = fi.fd,
        name = fi.name, parent = "ffff:", action = "drop", classid=1)


print("Ready")

try:
    b.trace_print()
    #while True:
    #    packet_str = os.read(fd, 4096)
    #    print(f'Userspace got data: {packet_str}')
except KeyboardInterrupt:
    print("unloading")

exit()