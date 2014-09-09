Pinjectme
=========

This is my first program, a simple Packet Injector created in python 
that allows you to inejct tcp flags to a given tagrget host
Usage : 

  pinjectme.py <TCP_FLAG> <Destination_IP> <Dport>
  pinjectme.py s|S|syn 172.16.122.1 22
Examples :
  pinjectme.py s 172.16.122.1 80 # sending Syn flags to 172.16.122.1 on port 80
  pinjectme.py x 172.16.122.1 80 # set all flags into a packet 
  
  
  
