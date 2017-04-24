# reflected-dns-ipv6-bind-shell
This is more than PoC I've made in python, but it's working almost the same.

# Disclaimer

  This code has lot of vulnerabilities like buffer overflowfs, and memory managment problems.
  I apologize, but by now I don't have enough time to repair this code.
  The main funcionality of the program in the moment is OK.
  
# How it works

  The shell is communicating with dns server, spoofing the source ip, so the packets are being 'reflected' to real receiver. 
  This connection tehinque may bypass some firewalls, and provide uniqe way of getting shell :)
  
# Author 
@Srakai (swientymateusz at gmail d0t com)
