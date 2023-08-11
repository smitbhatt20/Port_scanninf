import regex
from scapy.all import *

try:
    host = input("Enter a host address:")
    p = list(input("Enter the ports to scan:").split(",")) #Split is the method that converts strings into list
    temp = map(int,p) #to enter the ports in the integer instead of strings
    ports = list(temp)

    if(re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",host)): #regex -> characters into a fix pattern
        print("\n\nScanning...")
        print("Host: ", host)
        print("Ports: ",ports)

        ans , unans = sr(IP(dst=host)/TCP(dport=ports,flags="S"),verbose=0, timeout=2)
        for (s,r) in ans:
            print("[+] {} Open".format(s[TCP].dport))

except (ValueError,RuntimeError,TypeError,NameError):
    print("[~] Some Error Occured")
    print("[~] Exiting..")
