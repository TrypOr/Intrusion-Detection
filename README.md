# Intrusion-Detection-
An intrusion detection program in c

This is a basic packet analyzer that reads a packet capture file in the PCAPNG format and prints out some information about the packets it contains. The packet analyzer 
is written in C and uses the PCAP library to read the packet capture file.

The main purpose of this packet analyzer is to extract the source and destination IP addresses and port numbers of each packet in the capture file and write the information to a file named "result.txt".If a packet's information is the same to the information contained in "alerts.txt" ,we have encountered an intrusion,which is printed in the console.
