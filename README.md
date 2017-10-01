# reflected-dns-ipv6-bind-shell
  This project is smillar to PoC I've made in python, and it's working almost the same, the diffrence is, it's made in C, and on raw sockets.

# Disclaimer

  As this code was intended to be just PoC, it might not be the best quality.
  The main funcionality of the program at this moment is OK.
  
  I'm not responsible for any usage of this PoC tool
  
# How it works

  The shell is communicating with dns server, spoofing the source ip, so the packets are being 'reflected' to real receiver.
  
  SENDER <---spoofed ip addr---> DNS_SERVER <---dns server replies to our receiver---> RECEIVER
                        
  This connection tehinque may bypass some firewalls, and provide uniqe way of getting shell :)
  
# Author 
me
