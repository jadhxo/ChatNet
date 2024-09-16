# ChatNet
ChatNet is a chat application using TCP/IP to enable reliable message exchange between two machines. It handles packet loss, avoids duplicates, and ensures message ordering using TCP-like retransmission. The app also supports simultaneous text and file transfer, with synchronization for reconnecting peers.
This application runs a simple peer-to-peer connection between two servers.
----------------------------------------------------------------------------

Step 1

	---> Start up two different devices running any Debian based Operatring System (Ubuntu,Kali,...)
 
Step 2

	---> Open the terminal in the path of the udp.py server file on the respective machines
	---> Run the files on both machines using the command
 
		python3 udp.py <local_port> <destinantion_address> <destination_port>
			where <local_port> is the port of the corresponding machine
			and   <destination_address> is the IP Address of the other machine
			and   <destination_port> is the port of the other machine
   
	     For example:
			 If the command on Ubuntu was
				python3 udp.py 12345 192.168.233.128 12346 ---> 12345 is the local_port on the device running Kali, 192.168.233.128 is the IP Address and 12346 is the destination_port which is the local_port of the device running Kali
			 then the command on Kali would be
				python3 udp.py 12346 192.168.233.129 12345 ---> 12346 is the local_port on the device running Ubuntu, 192.168.233.129 is the IP Address and 12345 is the destination_port which is the local_port of the device running Ubuntu
    
Step 3

	---> After running these two commands on seperate devices, a text message GUI will appear
	---> In the text box, write any message and then click send.
	---> Upon clicking send, the message will appear as sent up top on the sender's side and the receiver will recieve the message along with an ACK number and the IP and local_port of the sender.
	---> The reveiver then can send a message back to the sender thus making it a peer-to-peer connection
 
Step 4

	---> If any one of the peers wants to send a file, click on the attachment icon below and select the intended item
	---> Since a file is attached, clicking send will invoke a TCP connection between the two peers to ensure a reliable transfer of the file

				
