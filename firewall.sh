#!/bin/bash

sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 5/min -j ACCEPT

sudo iptables -A INPUT -m string --string "malware" --algo bm -j DROP

sudo iptables -A INPUT -p udp --dport 53 -m string --string "malicious-domain.com" --algo bm -j DROP

sudo iptables -A INPUT -j LOG --log-prefix "Firewall-DROP:  "

sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP

sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/sec -j ACCEPT

sudo iptables -A INPUT -s 192.168.1.0/24 -j DROP 
