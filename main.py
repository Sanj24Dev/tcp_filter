from scapy.all import *
from os import system
from os.path import exists
import numpy as np

"""
    Function - search for TCP packets and extract relevant meta-data from the packets
    
    Arguments
        - file_name : str
          Name of the traffic file to parse and extract data from
    
    Returns
        - packet_list : list
          A list containing TCP packets
        - stores the information in a file - "capture_data.txt"
          
"""
def search_tcp(file_name):

    packet_list = []
    count = 0

    a = rdpcap(file_name)
    sessions = a.sessions()    

    for s in sessions:
        for packet in sessions[s]:
            try:
                count = count + 1
                # store packet information in a dictionary
                if packet.haslayer("TCP"):
                    packet_dict = {
                        "destPort": "",
                        "srcport" : "",
                        "destIP": "",
                        "srcIP": "",
                        "packet_sum" : "",
                        "flags" : ""
                    } 
                    packet_dict["packet_sum"] = packet.summary()
                    packet_dict["srcPort"] = packet["TCP"].sport
                    packet_dict["destPort"] = packet["TCP"].dport
                    packet_dict["destIP"] = packet["IP"].dst
                    packet_dict["srcIP"] = packet["IP"].src
                    F = packet["TCP"].flags
                    flags = ""
                    # check for presence of each flag bit
                    if(F & 0x01):
                        flags += "FIN "
                    if(F & 0x02):
                        flags += "SYN "
                    if(F & 0x04):
                        flags += "RST "
                    if(F & 0x08):
                        flags += "PSH "
                    if(F & 0x10):
                        flags += "ACK "
                    if(F & 0x20):
                        flags += "URG "
                    if(F & 0x20):
                        flags += "ECE "
                    if(F & 0x80):
                        flags += "CWR "
                    packet_dict["flags"] = ""
                    packet_dict["flags"] += flags
                    packet_list.append(packet_dict)
            except: 
                pass       

    # print traffic file info
    print("=========================================")
    print("Traffic File Summary for " + file_name)
    print("=========================================")
    print("Total number of sessions captured: \033[93m" + str(len(sessions)) + "\033[0m")
    print("Total number of packets: \033[93m" + str(count) + "\033[0m")
    print("Total number of TCP packets: \033[93m" + str(len(packet_list)) + "\033[0m")
    print("TCP packets as a percentage of total packets captured: \033[93m{0:.3f}%\033[0m".format((len(packet_list)/count) * 100))
    
    # writing the packet_list to a text file
    with open("capture_data.txt", 'a') as f:
        for packet in packet_list:
            strings_to_write = [
                "++++++++++++++++++++++++++++++++++++++",
                "\nSource IP Address: " + str(packet["srcIP"]),
                "\nDestination IP Address: " + str(packet["destIP"]),
                "\nSource port: " + str(packet["srcPort"]),
                "\nDestination port: " + str(packet["destPort"]),
                "\nFlags present: " + str(packet["flags"].strip()) + "\n"
            ]
            f.writelines(strings_to_write)
    return packet_list


"""
    Function - get the file_name as an input from the user
    
    Returns
    -------
    f_name : str
        Returns the file name of the file if the file/path exists
    False : Boolean
        Returns false if the file/path does not exists
"""

def get_file_name():   
    f_name = str(input("Enter file name or path to the traffic file (pcap file): "))
    file_exists = exists(f_name)
    if(file_exists):
        return f_name
    else:
        return False


"""
    Function - get the flag name to be searched as input from the user
    Returns
    -------
    f_name : str
        Flag name obtained as input
    False : Boolean
        If the flag is not one of the eight TCP flags, returns 'False'
"""

def get_flag_name():
    f_name = str(input("\nEnter a TCP flag to search for (among the TCP packets): "))
    if f_name in ["ACK", "SYN", "FIN", "RST", "PSH", "URG", "ECE", "CWR"]:
        return f_name
    return False

"""
    Function - search for the TCP packet containing the required filter flag. 
    The meta-data of packets containing the flag are then written 
    and stored into a file named 'flag_data.txt'
    Arguments
    ----------
    flag : str
        Flag to filter the packet list by
    packet_list : list
        List of TCP packets
        file with the flag traffic - "filter.txt"
"""


def search_tcp_flag(flag, packet_list):
    filtered = []
    
    for packet in packet_list:
        # checks if the given flag is present on the particular packet
        if flag in packet["flags"].split(" "):
            filtered.append(packet)
        else:
            pass
    
    open("filter.txt", "w").close()
    with open("filter.txt", 'a') as f:
        for flag_pack in filtered:
            strings_to_write = [
                "++++++++++++++++++++++++++++++++++++++",
                "\nSource IP Address: " + str(flag_pack["srcIP"]),
                "\nDestination IP Address: " + str(flag_pack["destIP"]),
                "\nSource port: " + str(flag_pack["srcPort"]),
                "\nDestination port: " + str(flag_pack["destPort"]),
                "\nFlags present: " + str(flag_pack["flags"].strip()) + "\n"
            ]
            
            f.writelines(strings_to_write)
        
    print("\nNumber of packets with \033[91m\033[1m\033[4m" + flag + "\033[0m flag: " + str(len(filtered)))
    print("Packet data successfully saved to flag_data.txt")

"""
    Function - driver code for the filter
"""

def menu():
    print("\nTCP PACKET FLAG BASED FILTER MENU")
    print("1. Choose a TCP flag")
    print("2. View the new report file for the flag entered")
    print("3. View the report file for the entire capture")
    print("4. Enter a new capture file")
    print("5. Exit")
    choice = int(input("Enter a choice: "))
    print("\n")
    _ = system('clear')
    if choice < 1 or choice > 5:
        print("Enter a valid choice")
        return 0
    return choice

def main():

    """
    Function - driver code for the program

    """
    
    while(1):

        # choose a traffic file
        _ = system('clear')
        open("capture_data.txt", "w").close()
        print("Choose a traffic file")

        # getting and validating the file
        file_name = get_file_name()
        
        if file_name == False:
            print("Incorrect file or path name!")
            return
        else:
            ext = file_name.split(".")
            if(ext[1] == "pcap"):
                print()
            else:
                print("File type not accepted. Please give a valid pcap file.")
                
        
        pack_list = search_tcp(file_name)

        # choose a flag to filter
        while(1):
            #  choose an option from the menu
            option = menu()

            # choose a flag
            if option == 1:
                flag_to_search = get_flag_name()
                if flag_to_search != False:
                    print("\nSearching for packets with \033[91m\033[1m\033[4m" + flag_to_search + "\033[0m flag...")
                    search_tcp_flag(flag_to_search, pack_list)   

            # view the report                 
            elif option == 2:
                system('cat filter.txt')

            # view the entire report
            elif option == 3:
                system('cat capture_data.txt')
            
            # exit loop
            elif option == 4:
                break

            # exit from the application
            elif option == 5:
                quit()
                break
            # catch error 
            else:
                print("\nAn error occurred\n")
                break

if __name__ == "__main__":
    main()
