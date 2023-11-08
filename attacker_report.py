#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Name: Gavin Fletcher
Date: 11/8/23
Version: 1.0
'''
#Import useful package(s)
import re
import geoip
from geoip import geolite2


def parse_file(fileName): # Takes a filename and a dictioanry to store the data in for later use
    dict_info = {}
    file = open(fileName, "r")
    IPPattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') # Regex for IP
    #pamPattern = re.compile(r'\bPAM\b (\d+) more authentication failures') # Re for PAM messages
    for line in file:
        currentLine = line.strip() # Get the current line in the file and remove the newline character
        if currentLine.find('authentication failure;') >= 0 or currentLine.find('Failed password for') >= 0:
            result = IPPattern.search(currentLine)
            if result == None:
                continue
            else:
                if geolite2.lookup(result[0]) == None: # Check if the country exists in geolite db
                    break
                elif (result[0] in dict_info.keys()): # This IP has already been marked so increase the count
                    dict_info[result[0]][1] += 1 # Increase the count by +1
                else: # The IP has not been seen before and we need to indentify the country and start the count at 1
                    dict_info[result[0]] = [geolite2.lookup(result[0]).country, 1] # Get country from IP and make count 1

        elif currentLine.find("PAM") >= 0:
            result = pamPattern.search(currentLine)
            IPResult = IPPattern.search(currentLine)
            if result == None: # If one result is none we dont need to worry about the other
                continue
            else:
                #int(result.group(1)) returns the number after PAM so we can add that count
                # IPResult[0] returns the IP address
                if geolite2.lookup(IPResult[0]) == None: # Check if the country exists in geolite db
                    break
                elif (IPResult[0] in dict_info.keys()): # This IP has already been marked so increase the count
                    dict_info[IPResult[0]][1] += int(result.group(1)) # Increase the count by +1
                else: # The IP has not been seen before and we need to indentify the country and start the count at 1
                    dict_info[IPResult[0]] = [geolite2.lookup(IPResult[0]).country, int(result.group(1))] # Get country from IP and make count  equal to the authentication failure (incase this is the first time)
    file.close() # Close the file
    return dict_info # Return the completed dictionary
def main():
    try:
       # returns a Dictionary where IP = key, and each value is a list containing [country, count]
       attack_info = parse_file("syslog.log")
       print("IP\t\tCount\t\tCountry")
       for ip, data in attack_info.items():
           print(attack_info)
           country, count = data
           #if (count > 10):
           print(f"{ip}\t\t{count}\t\t{country}")
    except IOError:
        print("The log file could not be found, aborting")
if __name__ == "__main__":
    main()
