#!/bin/bash


python triggerSniff.py
tcpdump -s0 -w cap.pcap & sleep 60s && pkill tcpdump
echo "Observed Macs"
python listMacs.py cap.pcap | sort | uniq -c

