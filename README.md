turn off firewall or unlock packet forwarding
##### OpenSuSE
```ssh
$ /sbin/SuSEfirewall2 off
```

enable forwarding:
``` ssh
$ echo 1 > /proc/sys/net/ipv4/ip_forward
```

firewall rules to block dns traffic:
``` ssh
$ iptables -A FORWARD -p tcp --dport 53 -j DROP
$ iptables -A FORWARD -p udp --dport 53 -j DROP
```
### TODO:
turn off ARP reply in server to prevent duplicate mac entry in target ARP table.

