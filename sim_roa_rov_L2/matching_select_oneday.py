import random 
import pickle
import ipaddress
import requests
import pandas as pd
import glob
import os
import scipy
from scipy.optimize import minimize_scalar
import numpy as np
import shutil
import time
from util import *
import pyasn
import random
from pyscipopt import Model
import re
from bs4 import BeautifulSoup
import requests
import copy
from ipaddress import ip_network
from decimal import *

# downloaded tor user/country distribution: https://metrics.torproject.org/userstats-relay-table.html?start=2021-05-01&end=2023-05-31
UserPerCountry = {'US': 0.2423, 'RU': 0.1543, 'DE': 0.07980000000000001, 'NL': 0.040999999999999995, 'FR': 0.0346, 'ID': 0.0277, 'GB': 0.0256, 'IN': 0.0254, 'UA': 0.0215, 'LT': 0.0178}
countries = list(UserPerCountry.keys())
cweights = list(UserPerCountry.values())

def weighted_sum(weights):
    prob = []
    for w in weights:
        prob.append(w/sum(weights))
    
    s = 0
    for i in range(len(weights)):
        s += weights[i] * prob[i]

    return s


def get_prefix_addresses_map():
    #maps prefix e.g. /19, /18, to the number of possible client within this prefix 
    '''
    return a map of IP prefix to number of possible users. 
    used to quickly sum up the number of possible IPv4 announced within an AS 
    
    /32 -> 0 client 
    /31 -> 2 clients 
    '''
    prefixMap = dict()
    for i in range(0,33):
        if 2**(32-i) - 2 > 0:
            prefixMap[i] = 2**(32-i) -2
        elif i == 32:
            prefixMap[i] = 0
        elif i == 30 or i == 31:
            prefixMap[i] = 2
    return prefixMap

def get_roas(filename):
    '''
    input a roa csv file and output a list of list containing each roa’s info 
    [IPnetwork, max len, prefix len, ASN]

    :param filename: (string) name to the .csv file containing ROA information 

    :return: (list) a nested list containing all ROA is the format: [IPnetwork, max len, prefix len, ASN]

    '''
    # read csv file
    ipv4s = []
    with open(filename, 'r') as f:
        csvreader = csv.reader(f)
        # skip fields
        next(csvreader)
        # append ip to roas list
        for row in csvreader:
            try:
                ipv4 = ipaddress.IPv4Network(row[1])
                maxlen = row[2]
                prefixlen = row[1].split('/')[1]
                #to account for different ROA file format
                if 'AS' not in row[0]:
                    asn = row[0]
                else:
                    asn = row[0][2:]
                ipv4s.append([ipv4, maxlen, prefixlen, asn])
            except ipaddress.AddressValueError: 
                #ignore cases where the address is ipv6 
                continue



    return ipv4s

def coverage_dict2(roas, ipv4s, make_pickle=False):
    '''
    given a list of IP addresses make a dictionary that maps IP address -> roa coverage info, if 
    the IP is not covered IP -> None. 
    format: IP ->  [IPnetwork, max len, prefix len, ASN]

    :param roas: (string) filename to the .csv file for ROA 
    :param ipv4s: (list) list of IPv4 addresses that needs to know their ROA coverage 
    :param make_pickle: (boolean) specify whether the resulting dictionary will be pikled for future use 
    '''
    # get ROA nets
    v4nets = get_roas(roas) # [ip network obj, maxlen, prefixlen, asn]
    # set up coverage dicts
    v4coverage = dict()

    # loop through all ip addresses
    for ip in ipv4s:
        ip_addr = ipaddress.IPv4Address(ip)
        v4coverage.setdefault(ip, None)
        for net in v4nets:
            if ip_addr in net[0]:
                v4coverage[ip] = net
                break

    if make_pickle:
        with open('coverage.pickle', 'wb') as f_cd1:
            pickle.dump(v4coverage, f_cd1)
    return v4coverage

def assignCountry(numUsers, countries, cweights, selection_algo):
    '''
    generate the desired number of users and assign country randomly to each client based on the TOR user per country stats. 
    Also assigns guard selection algo to each client. Both countries and cweights are global variable declared at the beginning of 
    the file. 

    :param numUsers: (int) number of clients generated 
    :param countries: (list) list of countries of possible TOR user origin 
    :param cweights: (list) weight of each country in the selection process. 
    :param selection_algo: (string) selection algorithm for guards, choose from vanilla, matching or input the discount value (e.g. 0.9)

    :return: (list) a list of client objects with country and selection algo assigned
    '''
    chosenCountry =  random.choices(countries, weights = cweights, k =  numUsers) #choose country based on tor's user / country data weight
    clientList  =[] # list populated with client obj filled in with origin 

    #iterate through all chosen client location and create new client obj
    for i in chosenCountry:
        newClient = Client(selection_algo)
        newClient.origin = i
        clientList.append(newClient)
    return clientList

def assignASN(numUsers, countries, cweights, selection_algo, roaFile, make_pickle = True):
    '''
    Generate client object with countries and ASN assigned to each. The ASN are assigned by choosing randomly within the client's 
    country's ASN. The weight of the ASN selection process is based on which AS announce the most IP addresses. After the AS is assigned to client,
    an IP address within the AS is randomly assigned to the client. 

    :param numUsers: (int) number of clients generated 
    :param countries: (list) list of countries of possible TOR user origin 
    :param cweights: (list) weight of each country in the selection process. 
    :param selection_algo: (string) selection algorithm for guards, choose from vanilla, matching or input the discount value (e.g. 0.9)
    :param roaFile: (string) filename to .csv file containing ROA information to check for roa coverage 
    :param make_pickle: (boolean) specify whether to make coverage dict for future use

    :return: (list) a list of client objects with country, ASN, roa/rov coverage, and selection algo assigned
    '''

    prefixHosts = get_prefix_addresses_map() # prefix -> number of ip address
    clientList = assignCountry(numUsers, countries, cweights, selection_algo)
    ASdict = dict() #country -> list of AS object
    weightdict = dict() # country -> weight of each AS
 
    ClientListwASN = [] #resulting list of clients that has the ASN filled in 
    
    specs = [0,0,0,0] #roa_rov, roa, rov, neither

        
    #iterate through pickled file and group ASN by country and populate 2 dict
    #ASdict: origin-> list of AS
    #weightdict: origin -> number of IPv4 each AS announce (acts as the weight of the random selection)
    file =  open('ASNnumIP.pickle', 'rb')
    numIPdict = pickle.load(file) # open pickled file, ASN -> AS object with numIPv4 filled in 
    file.close()
    for i in numIPdict: 
        if numIPdict[i].origin not in ASdict.keys():
            ASdict[numIPdict[i].origin] = [numIPdict[i]] 
            weightdict[numIPdict[i].origin] = [numIPdict[i].numIPv4]
        else:
            ASdict[numIPdict[i].origin].append(numIPdict[i])
            weightdict[numIPdict[i].origin].append(numIPdict[i].numIPv4)
    #iterate through clientList chose from assignCountry, randomly chose an ASN within that country 
    ipv4s = []
    for c in clientList:
        c.AS = random.choices(ASdict[c.origin], weights = weightdict[c.origin], k = 1)[0]
        prefixWeights = []
        for i in c.AS.prefixes:
            prefix = i.split('/')[1]
            prefixWeights.append(prefixHosts[int(prefix)])
  
        IPaddressPrefix = random.choices(c.AS.prefixes, weights = prefixWeights, k  = 1)
        IP = IPaddressPrefix[0].split('/')[0].split(".")
        prefix = int(IPaddressPrefix[0].split('/')[1])
        ipBin = ""
        for oct in IP:
            ipBin += '{0:08b}'.format(int(oct))
        choiceBitslen = 32- prefix
        choiceBits = ""
        resultIPBin = ""
        while resultIPBin == "":
            for i in range(choiceBitslen):
                choiceBits += str(random.choices([0,1], k = 1)[0]) 
            if choiceBits != "1"*choiceBitslen or choiceBits != "0"*choiceBitslen:
                resultIPBin = ipBin[0:prefix] + choiceBits
        resultIP = str(int(resultIPBin[0:8], 2)) + '.' + str(int(resultIPBin[8:16], 2)) + '.' + str(int(resultIPBin[16:24], 2)) + '.' + str(int(resultIPBin[24:32], 2))
        c.ipaddress = resultIP
        ipv4s.append(c.ipaddress)
        c.prefix = IPaddressPrefix
        ClientListwASN.append(c)
    

    #get coverage dict from the roa csv file 
    # if make_pickle == True:
    if True:
        cdict = coverage_dict2(roaFile, ipv4s, make_pickle=True)
    else:
        file = open('coverage.pickle', 'rb')
        cdict = pickle.load(file)
    

    #specs = [0,0,0,0] #roa_rov, roa, rov, neither
    #iterate through the clients 
    for c in ClientListwASN:
        # find all guard candidates


        #get the roa entry from csv from coverage dict which returns ip -> [ip network obj, maxlen, prefixlen, asn]
       
        c.roa = cdict[c.ipaddress]

        #if roa does not exist then its not covered 
        if c.roa == None:
            c.roaCovered = False
            # print("roa does not exist")
            if check_rov(c.AS.ASN):
                specs[2] += 1
            else:
                specs[3] += 1
        #if the asn announced does not match the asn from roa file the its invalid or if the prefix annouunced is more specific than the roa specified it is invalid 
        elif c.AS.ASN != c.roa[3] or c.roa[1] < c.prefix[0].split('/')[1]:
            # print("roa invalid")
            c.roaCovered = False
            if check_rov(c.AS.ASN):
                specs[2] += 1
            else:
                specs[3] += 1
        #otherwise it is covered 
        else:
            c.roaCovered = True
            # print("roa Covered in making client")
            if check_rov(c.AS.ASN):
                specs[0] += 1
            else:
                specs[1] += 1

    return ClientListwASN, specs

def check_roa_pre(roaFile):
    '''
    make an indirect dictionary to check for roa coverage based on IP address. This indirect dictionary works by assigning all ROA coverage information 
    with the same first octet in the same dictionary entry. In this way, to check an IP address' coverage, the program only need to iterate through 
    ROA entry of the same first octet, thus it will decrease the runtime of check up. 

    :param roaFile: (string) filename to the .csv file containing ROA info 

    :return: (dictionary) indirect dictionary, octet -> [list of roa coverage info]
    '''
    roaDict = dict() #octet -> [list of roa coverage info]
    for i in range(1,256):
        roaDict[str(i)] = []
    path = "../mergedROAs/" + roaFile
    with open(path) as f1:
        f1.readline()
        for line in f1:
            line = line.split(',')
            if ":" not in line[1]:
                if "AS" in line[0]:
                    if line[2].strip() == "":
                        line[2] = line[1].split('/')[1]
                    roaDict[line[1].split('.')[0]].append([int(float(line[0][2:].strip())), ipaddress.IPv4Network(line[1]), int(float(line[2]))])
                else:
                    roaDict[line[1].split('.')[0]].append([int(float(line[0].strip())), ipaddress.IPv4Network(line[1]), int(float(line[2]))])
    
    return roaDict

def check_roa(client, roaDict):
    '''
    returns the ROA coverage info using the indirect dictionary created above. 

    :param client: client object that need coverage check  
    :param roaDict: indirect dictionary created using the check_roa_pre() function 

    :return: (boolean) true or false value indicating the ROA coverage status of the client 
    '''
    prefixes = roaDict[client.ipaddress.split('.')[0]]

    for prefix in prefixes:
        # print(client.ipaddress)
        if ipaddress.IPv4Address(client.ipaddress) in prefix[1]:
            if int(client.AS.ASN) == prefix[0] and int(client.prefix[0].split('/')[1]) <= prefix[2]:
                return True
            else:
                return False
     
    return False

def lp_optimization(bws, roas, rovs, croas_both, crovs_both, croas_roa, crovs_roa, croas_rov, crovs_rov, croas_neither, crovs_neither, client_dist):   
    # print("sanity check")
    # print("len bws = number of relays = ", len(bws))
    # print("len roas = number of relays = ", len(roas))
    # print("len crovs_rov = ", len(crovs_rov))
    # print("client dist = ", client_dist)

    c_both1 = 0
    c_both2 = 0
    c_roa1 = 0
    c_roa2 =0
    c_rov1 = 0
    c_rov2 = 0
    c_neither1 = 0
    c_neither2 = 0

    for i in range(len(croas_both)):
        c_both1 += croas_both[i]

    for i in range(len(crovs_both)):
        c_both2 += crovs_both[i]

    # print("c_both1 = ", c_both1)
    # print("c_both2 = ", c_both2)


    for i in range(len(croas_roa)):
        c_roa1 += croas_roa[i]

    for i in range(len(crovs_roa)):
        c_roa2 += crovs_roa[i]

    # print("C_roa1 = ", c_roa1)


    for i in range(len(croas_rov)):
        c_rov1 += croas_rov[i]

    for i in range(len(crovs_rov)):
        c_rov2 += crovs_rov[i]

    # print("c_rov1 = ",c_rov1)
    # print("c_rov2 = ", c_rov2)


    for i in range(len(croas_neither)):
        c_neither1 += croas_neither[i]
    
    for i in range(len(crovs_neither)):
        c_neither2 += crovs_neither[i]

    # print("c_neither1 = ", c_neither1)
    # print("c_neither2 = ", c_neither2)
    # print("len crovs neither = ", len(crovs_neither))

    # normalize weights - use as prob
    sum_weights = sum(bws)
    weights_normalized = []
    for i in range(len(bws)):
        weights_normalized.append(bws[i]/sum_weights)

    # parameter - default
    load = 0.8
    theta = 5 
    penalty_norov = 0.9
    penalty_noroa = 0.7
    penalty_nothing = penalty_norov * penalty_noroa
    n = len(bws)
    matched_bonus = 1.5
    
    model = Model("weight_distribution")

    x = []
    for i in range(4*len(roas)):
        i = model.addVar(lb = 0, ub = 1, name="x"+str(i))
        x.append(i)

    # setup optimization
    # objective function - compute the weighted average matched rate
    covered = []
    covered2 = []
    
    # client group for both
    for i in range(len(roas)):
        c_sum = 0
        c_pro = 1
        for j in range(len(croas_both)):
            # client has both and guard has both - no penalty
            if croas_both[j] == 1 and crovs_both[j] == 1 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= 1*matched_bonus
                c_sum += 1*matched_bonus
            # client has both and guard has roa only - no penalty
            elif croas_both[j] == 1 and crovs_both[j] == 1 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_norov*matched_bonus
                c_sum += penalty_norov*matched_bonus
            # client has both and guard has rov only - no penalty
            elif croas_both[j] == 1 and crovs_both[j] == 1 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_noroa*matched_bonus
                c_sum += penalty_noroa*matched_bonus
            # client has both and guard has neither - penalty nothing
            elif croas_both[j] == 1 and crovs_both[j] == 1 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_nothing
                c_sum += penalty_nothing
            # client has roa only and guard has both - no penalty
            elif croas_both[j] == 1 and crovs_both[j] == 0 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_norov*matched_bonus
                c_sum += penalty_norov*matched_bonus
            # client has roa only and guard has roa only - penalty no rov
            elif croas_both[j] == 1 and crovs_both[j] == 0 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_norov * penalty_norov
                c_sum += penalty_norov * penalty_norov
            # client has roa only and guard has rov only - no penalty
            elif croas_both[j] == 1 and crovs_both[j] == 0 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_norov * penalty_noroa* matched_bonus
                c_sum += penalty_norov * penalty_noroa* matched_bonus
            # client has roa only and guard has neither - penalty no rov
            elif croas_both[j] == 1 and crovs_both[j] == 0 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_norov * penalty_nothing
                c_sum += penalty_norov * penalty_nothing
            # client has rov only and guard has both - no penalty
            elif croas_both[j] == 0 and crovs_both[j] == 1 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_noroa * matched_bonus
                c_sum += penalty_noroa * matched_bonus
            # client has rov only and guard has roa only - no penalty
            elif croas_both[j] == 0 and crovs_both[j] == 1 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_noroa * penalty_norov * matched_bonus
                c_sum += penalty_noroa * penalty_norov * matched_bonus
            # client has rov only and guard has rov only - penalty no roa
            elif croas_both[j] == 0 and crovs_both[j] == 1 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_noroa * penalty_noroa
                c_sum += penalty_noroa * penalty_noroa
            # client has rov only and guard has neither - penalty no roa
            elif croas_both[j] == 0 and crovs_both[j] == 1 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_noroa * penalty_nothing
                c_sum += penalty_noroa * penalty_nothing
            # client has neither and guard has both
            elif croas_both[j] == 0 and crovs_both[j] == 0 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_nothing
                c_sum += penalty_nothing
            # client has neither and guard has roa only
            elif croas_both[j] == 0 and crovs_both[j] == 0 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_nothing * penalty_norov
                c_sum += penalty_nothing * penalty_norov
            # client has neither and guard has rov only
            elif croas_both[j] == 0 and crovs_both[j] == 0 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_nothing * penalty_noroa
                c_sum += penalty_nothing * penalty_noroa
            # client has neither and guard has neither
            else:
                c_pro *= penalty_nothing * penalty_nothing
                c_sum += penalty_nothing * penalty_nothing
        covered.append((c_pro))
        covered2.append((c_sum))

    # client group for roa only
    for i in range(len(roas)):
        c_sum = 0
        c_pro = 1
        for j in range(len(croas_roa)):
            # client has both and guard has both - no penalty
            if croas_roa[j] == 1 and crovs_roa[j] == 1 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= 1 *matched_bonus
                c_sum += 1 * matched_bonus
            # client has both and guard has roa only - no penalty
            elif croas_roa[j] == 1 and crovs_roa[j] == 1 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_norov * matched_bonus
                c_sum += penalty_norov * matched_bonus
            # client has both and guard has rov only - no penalty
            elif croas_roa[j] == 1 and crovs_roa[j] == 1 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_noroa * matched_bonus
                c_sum += penalty_noroa * matched_bonus
            # client has both and guard has neither - penalty nothing
            elif croas_roa[j] == 1 and crovs_roa[j] == 1 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_nothing
                c_sum += penalty_nothing
            # client has roa only and guard has both - no penalty
            elif croas_roa[j] == 1 and crovs_roa[j] == 0 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_norov * matched_bonus
                c_sum += penalty_norov * matched_bonus
            # client has roa only and guard has roa only - penalty no rov
            elif croas_roa[j] == 1 and crovs_roa[j] == 0 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_norov * penalty_norov
                c_sum += penalty_norov * penalty_norov
            # client has roa only and guard has rov only - no penalty
            elif croas_roa[j] == 1 and crovs_roa[j] == 0 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_norov * penalty_noroa * matched_bonus
                c_sum += penalty_norov * penalty_noroa * matched_bonus
            # client has roa only and guard has neither - penalty no rov
            elif croas_roa[j] == 1 and crovs_roa[j] == 0 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_norov * penalty_nothing
                c_sum += penalty_norov * penalty_nothing
            # client has rov only and guard has both - no penalty
            elif croas_roa[j] == 0 and crovs_roa[j] == 1 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_noroa * matched_bonus
                c_sum += penalty_noroa * matched_bonus
            # client has rov only and guard has roa only - no penalty
            elif croas_roa[j] == 0 and crovs_roa[j] == 1 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_noroa * penalty_norov * matched_bonus
                c_sum += penalty_noroa * penalty_norov * matched_bonus
            # client has rov only and guard has rov only - penalty no roa
            elif croas_roa[j] == 0 and crovs_roa[j] == 1 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_noroa * penalty_noroa
                c_sum += penalty_noroa * penalty_noroa
            # client has rov only and guard has neither - penalty no roa
            elif croas_roa[j] == 0 and crovs_roa[j] == 1 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_noroa * penalty_nothing
                c_sum += penalty_noroa * penalty_nothing
            # client has neither and guard has both
            elif croas_roa[j] == 0 and crovs_roa[j] == 0 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_nothing
                c_sum += penalty_nothing
            # client has neither and guard has roa only
            elif croas_roa[j] == 0 and crovs_roa[j] == 0 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_nothing * penalty_norov
                c_sum += penalty_nothing * penalty_norov
            # client has neither and guard has rov only
            elif croas_roa[j] == 0 and crovs_roa[j] == 0 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_nothing * penalty_noroa
                c_sum += penalty_nothing * penalty_noroa
            # client has neither and guard has neither
            else:
                c_pro *= penalty_nothing * penalty_nothing
                c_sum += penalty_nothing * penalty_nothing
        covered.append((c_pro))
        covered2.append((c_sum))

    # client group for rov only
    for i in range(len(roas)):
        c_sum = 0
        c_pro = 1
        for j in range(len(croas_rov)):
            # client has both and guard has both - no penalty
            if croas_rov[j] == 1 and crovs_rov[j] == 1 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= 1 * matched_bonus
                c_sum += 1 * matched_bonus
            # client has both and guard has roa only - no penalty
            elif croas_rov[j] == 1 and crovs_rov[j] == 1 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_norov * matched_bonus
                c_sum += penalty_norov * matched_bonus
            # client has both and guard has rov only - no penalty
            elif croas_rov[j] == 1 and crovs_rov[j] == 1 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_noroa * matched_bonus
                c_sum += penalty_noroa * matched_bonus
            # client has both and guard has neither - penalty nothing
            elif croas_rov[j] == 1 and crovs_rov[j] == 1 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_nothing
                c_sum += penalty_nothing
            # client has roa only and guard has both - no penalty
            elif croas_rov[j] == 1 and crovs_rov[j] == 0 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_norov * matched_bonus
                c_sum += penalty_norov * matched_bonus
            # client has roa only and guard has roa only - penalty no rov
            elif croas_rov[j] == 1 and crovs_rov[j] == 0 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_norov * penalty_norov
                c_sum += penalty_norov * penalty_norov
            # client has roa only and guard has rov only - no penalty
            elif croas_rov[j] == 1 and crovs_rov[j] == 0 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_norov * penalty_noroa * matched_bonus
                c_sum += penalty_norov * penalty_noroa * matched_bonus
            # client has roa only and guard has neither - penalty no rov
            elif croas_rov[j] == 1 and crovs_rov[j] == 0 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_norov * penalty_nothing
                c_sum += penalty_norov * penalty_nothing
            # client has rov only and guard has both - no penalty
            elif croas_rov[j] == 0 and crovs_rov[j] == 1 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_noroa * matched_bonus
                c_sum += penalty_noroa * matched_bonus
            # client has rov only and guard has roa only - no penalty
            elif croas_rov[j] == 0 and crovs_rov[j] == 1 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_noroa * penalty_norov * matched_bonus
                c_sum += penalty_noroa * penalty_norov * matched_bonus
            # client has rov only and guard has rov only - penalty no roa
            elif croas_rov[j] == 0 and crovs_rov[j] == 1 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_noroa * penalty_noroa
                c_sum += penalty_noroa * penalty_noroa
            # client has rov only and guard has neither - penalty no roa
            elif croas_rov[j] == 0 and crovs_rov[j] == 1 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_noroa * penalty_nothing
                c_sum += penalty_noroa * penalty_nothing
            # client has neither and guard has both
            elif croas_rov[j] == 0 and crovs_rov[j] == 0 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_nothing
                c_sum += penalty_nothing
            # client has neither and guard has roa only
            elif croas_rov[j] == 0 and crovs_rov[j] == 0 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_nothing * penalty_norov
                c_sum += penalty_nothing * penalty_norov
            # client has neither and guard has rov only
            elif croas_rov[j] == 0 and crovs_rov[j] == 0 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_nothing * penalty_noroa
                c_sum += penalty_nothing * penalty_noroa
            # client has neither and guard has neither
            else:
                c_pro *= penalty_nothing * penalty_nothing
                c_sum += penalty_nothing * penalty_nothing
        covered.append((c_pro))
        covered2.append((c_sum))

    # client group for neither
    for i in range(len(roas)):
        c_sum = 0
        c_pro = 1
        for j in range(len(croas_neither)):
            # client has both and guard has both - no penalty
            if croas_neither[j] == 1 and crovs_neither[j] == 1 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= 1 * matched_bonus
                c_sum += 1 * matched_bonus
            # client has both and guard has roa only - no penalty
            elif croas_neither[j] == 1 and crovs_neither[j] == 1 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_norov * matched_bonus
                c_sum += penalty_norov * matched_bonus
            # client has both and guard has rov only - no penalty
            elif croas_neither[j] == 1 and crovs_neither[j] == 1 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_noroa * matched_bonus
                c_sum += penalty_noroa * matched_bonus
            # client has both and guard has neither - penalty nothing
            elif croas_neither[j] == 1 and crovs_neither[j] == 1 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_nothing
                c_sum += penalty_nothing
            # client has roa only and guard has both - no penalty
            elif croas_neither[j] == 1 and crovs_neither[j] == 0 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_norov * matched_bonus
                c_sum += penalty_norov * matched_bonus
            # client has roa only and guard has roa only - penalty no rov
            elif croas_neither[j] == 1 and crovs_neither[j] == 0 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_norov * penalty_norov
                c_sum += penalty_norov * penalty_norov
            # client has roa only and guard has rov only - no penalty
            elif croas_neither[j] == 1 and crovs_neither[j] == 0 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_norov * penalty_noroa * matched_bonus
                c_sum += penalty_norov * penalty_noroa * matched_bonus
            # client has roa only and guard has neither - penalty no rov
            elif croas_neither[j] == 1 and crovs_neither[j] == 0 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_norov * penalty_nothing
                c_sum += penalty_norov * penalty_nothing
            # client has rov only and guard has both - no penalty
            elif croas_neither[j] == 0 and crovs_neither[j] == 1 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_noroa * matched_bonus
                c_sum += penalty_noroa * matched_bonus
            # client has rov only and guard has roa only - no penalty
            elif croas_neither[j] == 0 and crovs_neither[j] == 1 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_noroa * penalty_norov * matched_bonus
                c_sum += penalty_noroa * penalty_norov * matched_bonus
            # client has rov only and guard has rov only - penalty no roa
            elif croas_neither[j] == 0 and crovs_neither[j] == 1 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_noroa * penalty_noroa
                c_sum += penalty_noroa * penalty_noroa
            # client has rov only and guard has neither - penalty no roa
            elif croas_neither[j] == 0 and crovs_neither[j] == 1 and roas[i] == 0 and rovs[i] == 0:
                c_pro *= penalty_noroa * penalty_nothing
                c_sum += penalty_noroa * penalty_nothing
            # client has neither and guard has both
            elif croas_neither[j] == 0 and crovs_neither[j] == 0 and roas[i] == 1 and rovs[i] == 1:
                c_pro *= penalty_nothing
                c_sum += penalty_nothing
            # client has neither and guard has roa only
            elif croas_neither[j] == 0 and crovs_neither[j] == 0 and roas[i] == 1 and rovs[i] == 0:
                c_pro *= penalty_nothing * penalty_norov
                c_sum += penalty_nothing * penalty_norov
            # client has neither and guard has rov only
            elif croas_neither[j] == 0 and crovs_neither[j] == 0 and roas[i] == 0 and rovs[i] == 1:
                c_pro *= penalty_nothing * penalty_noroa
                c_sum += penalty_nothing * penalty_noroa
            # client has neither and guard has neither
            else:
                c_pro *= penalty_nothing * penalty_nothing
                c_sum += penalty_nothing * penalty_nothing
        covered.append((c_pro))
        covered2.append((c_sum))    
    
    c = 0
    for i in range(len(x)):
        c += x[i]* covered2[i]

    c = c
    model.setObjective(c, "maximize")
    

    # dummy list to use linear combination format
    a = []
    for i in range(len(roas)):
        a.append(1)

    # for each variable, must be nonnegative
    for i in range(len(x)):
        model.addCons(x[i] >= 0, name="non_negative_x_" + str(i))        

    # for each subgroup, the total bandwidth should not exceed maximum global bandwidth
    c1 = 0
    for i in range(len(a)):
        c1 += x[i] * a[i]
                       
    model.addCons(c1 == 1, name="weight_sum_constraint_1")

    c2 = 0
    for i in range(len(a), len(a)*2):
        c2 += x[i] * a[i%len(roas)]

    model.addCons(c2 == 1, name="weight_sum_constraint_2")

    c3 = 0
    for i in range(2*len(a), 3*len(a)):
        c3 += x[i] * a[i%len(roas)]

    model.addCons(c3 ==1, name="weight_sum_constraint_3")

    c4 = 0
    for i in range(3*len(a), 4*len(a)):
        c4 += x[i] * a[i%len(roas)]

    model.addCons(c4 ==1, name="weight_sum_constraint_4")

    # c5 = 0
    # for i in range(len(roas)):
    #     c5 += abs(x[i] - weights_normalized[i])

    # model.addCons(c5 <= 0.01, name="percentage_change_total_limit")

    # each relay should not exceed its total bandwidth, summing across all possible cases
    for i in range(len(roas)):
        inde = i // len(roas) # group number
        r = i % len(roas) # relay number with in the group
        p = client_dist[0] * x[r] + client_dist[1] * x[r+len(roas)] + client_dist[2] * x[r+2*len(roas)] + client_dist[3] * x[r+3*len(roas)]

        model.addCons( p * sum(bws) * load <= bws[r], name="relay_bandwidth_constraint_"+str(i))

    # probability to choose each relay should not exceed theta times
    for i in range(len(roas)):
        inde = i // len(roas)
        r = i % len(roas)
        p = client_dist[0] * x[r] + client_dist[1] * x[r+len(roas)] + client_dist[2] * x[r+2*len(roas)] + client_dist[3] * x[r+3*len(roas)]
        model.addCons (p <= theta * weights_normalized[r], name="relay_placement_constraint_" + str(i))

    model.optimize()
          
    solution = model.getBestSol()
    
    weights_optimized = []

    solution2 = []
    
    for i in range(len(x)):
        weights_optimized.append(model.getVal(x[i]))   

    return weights_optimized

def check_rovset(asn, rovset):
    found = False
    for i in range(len(rovset)):
        rovset[i] = str(rovset[i])
        if int(asn) == int(rovset[i].strip()):
            found = True
            return found
    return found


# read in routeview file and output ASN->IP prefix - ipv4
def process_routeview_v4(routeviewPath):
    """
    process the routeview data
    return: ASN -> IP prefix
    """
    # print("processing ipv4 prefixes")
    map_dict = dict() #store each entry of routeview data, ip network -> asn 
    quick_dict = dict() #store starting index of each octet 
    routeviewFile = routeviewPath
    with open(routeviewFile) as tsv:
        count = 0
        num = 1
        quick_dict[num] = count
        for line in csv.reader(tsv, dialect = "excel-tab"):
            #iterate through each line in routeview data
            v4Network = ipaddress.IPv4Network(line[0] + '/' + line[1])
            map_dict[v4Network] = line[2] #network -> ASN 
            if int(line[0].split('.')[0]) != num:
                num += 1
                quick_dict[num] = count

            count += 1

    return map_dict, quick_dict

# read in routeview file and output ASN->IP prefix - ipv6
def process_routeview_v6(routeviewPath):
    """
    same logic and process as the v4 version 
    """
    # print("processing ipv6 prefixes")
    map_dict = dict()
    quick_dict = dict()
    routeviewFile = routeviewPath
    with open(routeviewFile) as tsv:
        count = 0
        num = '2001'
        quick_dict[num] = count
        for line in csv.reader(tsv, dialect = "excel-tab"):
            map_dict[ipaddress.IPv6Network(line[0] + '/' + line[1])] = line[2]
            if str(line[0].split(':')[0]) != num:
                num = line[0].split(':')[0]
                quick_dict[num] = count

            count += 1

    return map_dict, quick_dict

# read in consensus file and output list of relays and the corresponding wgd, wgg
def process_consensus(year, month, date, hour):
    ''' 
    process consensus file
    output: list of relays, (int) wgd, (int) wgg
    '''
    # Set up path
    cwd = os.getcwd()
    monthDirectory = r'/consensuses-' + year + '-' + month
    dateDirectory = '/' + date
    filename = '/' + year + '-' + month + '-' + date + '-' + hour + '-00-00-consensus'
    path = r'../archive' + monthDirectory + dateDirectory + filename
    # If file exists, open it
    try:
        with open(path, 'r') as f:
            lines = f.read().split('\n') #read all input, split with newline character
            rs = []
            # iterate through each line to get info on relay 
            for line in lines:
                # Bandwidth weights for this consensus
                if line.startswith('bandwidth-weights'):
                    bw_info = line.split()
                    wgd = (int(bw_info[12].split('=')[1]))  # WGD: weight for Guard+Exit-flagged nodes in guard position
                    wgg = (int(bw_info[13].split('=')[1]))  # WGG: weight for Guard-flagged nodes in guard position
                    break
                # put relay info into Relay object
                elif line[0] == 'r' and line[1] == ' ':
                    r_info = line.split('r ', 1)[1].split()
                    r = Relay(r_info[1], r_info[2], r_info[5])  # fp and ip
                    r.or_addresses = r_info[5]+":"+r_info[6]
                elif line[0] == 'a' and line[1] == ' ':
                    a_info = line.split('a [', 1)[1].split(']', 1)[0]
                    r.ipv6 = a_info # ipv6 if it exists
                elif line[0] == 's' and line[1] == ' ':
                    s_info = line.split('s ', 1)[1].split()  # s_info : list of flags
                    if all(f in s_info for f in ('Fast', 'Guard', 'Stable', 'V2Dir')):
                        r.is_guard = True
                    if 'Exit' in s_info:
                        r.is_exit = True
                elif line[0] == 'w' and line[1] == ' ':
                    bw = line.split('=')[1]  # bandwidth
                    if 'Unmeasured' not in bw:
                        r.bw = int(bw)
                    # append relay to list
                    rs.append(r)

    # If file does not exist, do nothing
    except FileNotFoundError:
        print(filename + ' not found.')
        return False, False, False
    #return the list of relay and WGD and WGG eahc file only has 1 of these for weighing the exit and guard realy
    return rs, wgd, wgg

# iterate through the list of dates and process consensus for each day and write all relays consensus to pickle day by day
def pickle_consensus(start_date, end_date):
    '''
    call archive_consensus to get a list of relay objects, pickle and move them into archive_pickles folder
    return set of IPv4 addresses and set of IPv6 addresses
    '''

    path = os.getcwd()
    # path = os.path.split(path)[0] + '//archive//'
    path = '../archive_pickles/'
    all_ipv4s = set()
    all_ipv6s = set()
    for t in datespan(start_date, end_date, delta=timedelta(hours=1)):
        #get relay objects in time duration
        rs, wgd, wgg = process_consensus(t.strftime('%Y'), t.strftime('%m'), t.strftime('%d'), t.strftime('%H'))
        if rs:
            #iterate through all relay and record ip addresses
            ipv4s = [r.ip for r in rs]
            ipv6s = [r.ipv6 for r in rs if r.ipv6 != '']
            all_ipv4s.update(ipv4s)
            all_ipv6s.update(ipv6s)
            filename = t.strftime('%Y') + '-' + t.strftime('%m') + '-' + t.strftime('%d') + '-' + t.strftime('%H') + '.pickle'
            #pickled consensus and move to archive_pickles folder
            with open(filename, 'wb') as f_pc1:
                pickle.dump(rs, f_pc1)
                pickle.dump(wgd, f_pc1)
                pickle.dump(wgg, f_pc1)
            # moves file into directory archive
            if os.path.exists(path+filename):
                os.remove(path+filename)
                shutil.move(filename, path)
            else:
                shutil.move(filename, path)
    return all_ipv4s, all_ipv6s

def get_prefix_and_asn_local_v4(ipstr):

    """
    input the 2 required dict and an IP address, return the prefix and asn 
    first dictionary decide which line to start looking by mapping the 1st octet to the index 
    in routeview file, than iterate through one by one to see 
    which asn annouces a prefix containing the ip address we are looking for 

    :praram qDict: (dict) indirect dictionary to get starting index in mapdict 
    :param mapdict: (dict) dictionary containing network -> asn 
    :param ipstr: (string) ip address we are searching in string format 

    """
    RIS_PREFIX = "https://stat.ripe.net/data/ris-prefixes/data.json?resource="

    ipm = _pyipmeta.IpMeta()
    prov = ipm.get_provider_by_name("pfx2as")
    print(ipm.enable_provider(prov, "-f http://data.caida.org/datasets/routing/routeviews-prefix2as/2017/03/routeviews-rv2-20170329-0200.pfx2as.gz"))
    print()

    # Map between ipv4 addresses and origin asns
    if ipm.lookup(ipstr):
        (res,) =  ipm.lookup(ipstr)
        if res.get('asns'):
            asn = res.get('asns')[-1]
        else:
            asn = ''
    else:
        asn = ''

    if asn == '':
        return '', []
    else:
        r = requests.get(RIS_PREFIX+str(asn)+"&list_prefixes=true&types=o&af=v4&noise=filter")
        if r.status_code > 200:
            for _ in range(0,2):
                print("Status code of previous request: {} - Waiting 5 seconds and retry".format(r.status_code))
                time.sleep(5)
                r = requests.get(RIS_PREFIX+str(asn)+"&list_prefixes=true&types=o&af=v4&noise=filter")
                if r.status_code < 300:
                    break

        asnInfo = r.json()
        #gives all prefix
        if r.status_code < 300:
            prefixes_originated = asnInfo['data']['prefixes']['v4']['originating']
        print("Fetched prefixes for AS{}".format(asn))
        
        return prefixes_originated, [asn]


#ipv6 version of the above methods 
def get_prefix_and_asn_local_v6(ipstr):
    """
    same logic and process as the v4 version 
    """

    RIS_PREFIX = "https://stat.ripe.net/data/ris-prefixes/data.json?resource="

    ipm = _pyipmeta.IpMeta()
    prov = ipm.get_provider_by_name("pfx2as")
    print(ipm.enable_provider(prov, "-f http://data.caida.org/datasets/routing/routeviews-prefix2as/2017/03/routeviews-rv2-20170329-0200.pfx2as.gz"))
    print()

    # Map between ipv4 addresses and origin asns
    if ipm.lookup(ipstr):
        (res,) =  ipm.lookup(ipstr)
        if res.get('asns'):
            asn = res.get('asns')[-1]
        else:
            asn = ''
    else:
        asn = ''

    if asn == '':
        return '', []
    else:
        r = requests.get(RIS_PREFIX+asn+"&list_prefixes=true&types=o&af=v6&noise=filter")
        if r.status_code > 200:
            for _ in range(0,2):
                print("Status code of previous request: {} - Waiting 5 seconds and retry".format(r.status_code))
                time.sleep(5)
                r = requests.get(RIS_PREFIX+asn+"&list_prefixes=true&types=o&af=v6&noise=filter")
                if r.status_code < 300:
                    break

        asnInfo = r.json()
        #gives all prefix
        if r.status_code < 300:
            prefixes_originated = asnInfo['data']['prefixes']['v6']['originating']
        print("Fetched prefixes for AS{}".format(asn))
        
        return prefixes_originated, [asn]



# read from dictionary the prefix and ASN of an IP
def get_prefix_and_asn_local(ip):
    """
    wrapper function to get prefix and ASN given an ip address

    :param ip: (str) ip address in string 

    :return: ip prefix in ipaddress module object, ASN 

    """
    if ':' in ip:
        # return get_prefix_and_asn_local_v6(ip)
        return '',[]
    if '.' in ip:
        return get_prefix_and_asn_local_v4(ip)

# map ip to asn and prefixes
def get_pre_asn(ipv4s, ipv6s, asndb, make_pickle=True, existing_file=False):
    """takes in list of ip addresses and find the corresponding ASN and ip prefix for each address. Each ip address is map 
    to a list with ASN and prefix 

    :param ipv4s: (list) list of ipv4 addresses
    :param ipv6s: (list) list of ipv6 addresses
    :make_pickle: (boolean) make pickle containing ip -> [prefix, ASN] dictionary if true
    :existing_file: (boolean) use previous pickle to save runtime for repeating ip addresses

    :return: 2 dictionaries for ipv4 and ipv6, each containing ip -> [prefix, ASN] 

    """
    # set up dicts
    ipv4s_asns = dict()
    ipv6s_asns = dict()

    # loop through ips
    if existing_file:
        new_ipv4s = set()
        new_ipv6s = set()
        with open('../relay_asns.pickle', 'rb') as ef:
            v4_asns = pickle.load(ef)
            v6_asns = pickle.load(ef)

        for ip in ipv6s:
            if ip in v6_asns:
                pre_asn = v6_asns[ip]
                ipv6s_asns.setdefault(ip, pre_asn)
            else:
                new_ipv6s.add(ip)
        for ip in ipv4s:
            if ip in v4_asns:
                pre_asn = v4_asns[ip]
                ipv4s_asns.setdefault(ip, pre_asn)
            else:
                new_ipv4s.add(ip)
        ipv4s = new_ipv4s
        ipv6s = new_ipv6s

    # ipv6s
    countv6 = 0
    for ip in ipv6s:
        # print("working on " + str(countv6) + " out of total = " + str(len(ipv6s)))
        asn, pre = asndb.lookup(ip)
        if asn != None:
            ipv6s_asns.setdefault(ip, [pre, asn])
        else:
            ipv6s_asns.setdefault(ip, [pre, None])

        countv6 += 1

    countv4 = 0
    for ip in ipv4s:
        # print("working on " + str(countv4) + " out of total = " + str(len(ipv4s)))
        asn, pre = asndb.lookup(ip)
        if asn != None:
            ipv4s_asns.setdefault(ip, [pre, asn])
        else:
            ipv4s_asns.setdefault(ip, [pre, None])
        countv4 +=1
    if make_pickle:
        with open('../relay_asns.pickle', 'wb') as f_pa:
            pickle.dump(ipv4s_asns, f_pa)
            pickle.dump(ipv6s_asns, f_pa)
    return ipv4s_asns, ipv6s_asns

# helper function to read roa coverage input
def get_roas(filename):
    '''parse roa file in .csv format, put each entry in a list, then append to a list containing all entries.
    each line in the file converts into [ipv4, maxlen, prefixlen, asn]

    :param filename: (string) name of the csv file to parse 
    :return: 2 lists of list for ipv4 and ipv6 addresses, entry in each list is [ipv4, maxlen, prefixlen, asn]
    ''' 
    # read csv file
    ipv4s = []
    ipv6s = []
    path = "../mergedROAs/" + filename
    with open(path, 'r') as f:
        csvreader = csv.reader(f)
        # skip fields
        next(csvreader)
        # append ip to roas list
        for row in csvreader:
            try:
                ipv4 = ipaddress.IPv4Network(row[1])
                maxlen = row[2]
                prefixlen = row[1].split('/')[1]
                #to account for different ROA file format
                if 'AS' not in row[0]:
                    asn = row[0]
                else:
                    asn = row[0][2:]
                ipv4s.append([ipv4, maxlen, prefixlen, asn])
            except ipaddress.AddressValueError:
                try:
                    ipv6 = ipaddress.IPv6Network(row[1])
                    maxlen = row[2]
                    prefixlen = row[1].split('/')[1]
                    if 'AS' not in row[0]:
                        asn = row[0]
                    else:
                        asn = row[0][2:]
                    ipv6s.append([ipv6, maxlen, prefixlen, asn])
                except:
                    pass
            except:
                pass

    return ipv4s, ipv6s

def load_consensus(p, year, month, date, hour):
    '''pulls list of relay object, weight info (wgd, wgg) from pickled file
    :param p: (str) path of pickle directory 
    :param year: (str) year of the consensus
    :param month: (str) month of the consensus
    :param date: (str) date of the consensus
    :param hour: (str) hour of the consensus

    :return: list of relay objects, wgd, wgg
    '''
    # load .pickle file
    filename = p + year + '-' + month + '-' + date + '-' + hour + '.pickle'
    try:
        file = open(filename, 'rb')
        rs = pickle.load(file)
        wgd = pickle.load(file)
        wgg = pickle.load(file)
        return rs, wgd, wgg
    # if it doesn't exist
    except FileNotFoundError:
        print('Consensus for ' + year + '-' + month + '-' + date + '-' + hour + ' doesn\'t exist.')
        return [], 0, 0

# map roa coverage to ip
def coverage_dict(roas, ipv4s, ipv6s):
    '''
    use roa file to check against ipv4 and ipv6 addresses to see if that relay is covered by roa
    make a new dict mapping ip address to its ROA coverage info, ip -> [ipv4, maxlen, prefixlen, asn]

    :param roas: (string) filename of the roa data 
    :param ipv4s: (list) list of ipv4s to check roa coverage
    :param ipv6s: (list) list of ipv6s to check roa coverage
    :param make_pickle: (boolean) if true, make pickle of the resulting dictionary (ip -> [ipv4, maxlen, prefixlen, asn]) into pick 

    :return: 2 dictionaries for ipv4 and ipv6 in ip -> [ipv4, maxlen, prefixlen, asn] format

    '''
    # get ROA nets
    v4nets, v6nets = get_roas(roas) # list of [ip network obj, maxlen, prefixlen, asn]
    # set up coverage dicts
    v4coverage = dict()
    v6coverage = dict()
    # loop through all ip addresses
    for ip in ipv4s:
        ip_addr = ipaddress.IPv4Address(ip)
        v4coverage.setdefault(ip, None)
        for net in v4nets:
            if ip_addr in net[0]:
                v4coverage[ip] = net
                break
    for ip in ipv6s:
        ip_addr = ipaddress.IPv6Address(ip)
        v6coverage.setdefault(ip, None)
        for net in v6nets:
            if ip_addr in net[0]:
                v6coverage[ip] = net
                break
    return v4coverage, v6coverage

# update consensus file to include roa info
def update_consensus_pickle(start_date, end_date, v4coverage, v6coverage, ipv4_asns, ipv6_asns):
    ''' update pickle in archive_pickles folder to contain ROA coverage and assign prefix and ASN

        :param start_date: (str) start date of the duration in needs update
        :param end_date: (str) end date of the duration in need of update
        :param v4coverage: (dict) input the result of coverage_dict function, mapping ip -> ROA info
        :param v6coverage: (dict) input the result of coverage_dict function, mapping ip -> ROA info
        :param ipv4_asns: (dict) input result from get_pre_asn, ip -> [prefix, ASN] 
        :param ipv6_asns: (dict) input result from get_pre_asn, ip -> [prefix, ASN] 
    '''
    p = os.getcwd()
    archivePath = '../archive_pickles/'
    resultPath = '../processed/'
    # iterate through consensus pickles
    for t in datespan(start_date, end_date, delta=timedelta(hours=1)):
        # load old pickle
        rs, wgd, wgg = load_consensus(archivePath, t.strftime('%Y'), t.strftime('%m'), t.strftime('%d'), t.strftime('%H'))
        if rs:
            updated_rs = []
            for r in rs:
                r.ipv4_prefix = ipv4_asns[r.ip][0]
                r.asn = ipv4_asns[r.ip][1]
                r.ipv4_roa = v4coverage[r.ip]
                if r.ipv6 != '':
                    r.ipv6_prefix = ipv6_asns[r.ipv6][0]
                    r.ipv6_asn = ipv6_asns[r.ipv6][1]
                    r.ipv6_roa = v6coverage[r.ipv6]
                    #if r.ipv6_asn != r.asn:
                    #    print(r.ip + ' in ' + str(r.asn) + '. ' + r.ipv6 + ' in ' + str(r.ipv6_asn))
                updated_rs.append(r)
            filename = t.strftime('%Y') + '-' + t.strftime('%m') + '-' + t.strftime('%d') + '-' + t.strftime('%H') + '-processed.pickle'
            with open(filename, 'wb') as f_ucp:
                pickle.dump(updated_rs, f_ucp)
                pickle.dump(wgd, f_ucp)
                pickle.dump(wgg, f_ucp)
            if os.path.exists(resultPath+filename):
                os.remove(resultPath+filename)
                shutil.move(filename, resultPath)
            else:
                shutil.move(filename, resultPath)
    return

# input ip prefix and return the max and min addresses within this prefix 
def get_max_min(ipPrefix):
    """
    input an IP prefix and return the highest and lowest IP address 

    :param ipPrefix: (string) IPv4 prefix 

    :return: (IPv4Address object) return the lowerst address and highest address 
    """
    range = [8,16,24,32] # used in the for loop below 

    ip  = ipPrefix.split('/')[0].split('.') #ip prefix before the slash and split between the dots 
    ipBin = '' #binary rep of the ip address
    prefix  = int(ipPrefix.split('/')[1]) # the prefix in int 

    #check if the prefix is 32, if it is 32 then there is no hosts and no max and mins 
    if prefix != 32:

        #get first part of ip prefix in binary form
        for oct in ip:
            ipBin += '{0:08b}'.format(int(oct))
            #got the above dec -> int operation from here: https://www.techiedelight.com/how-to-convert-an-integer-to-a-binary-string-in-python/
        

        temp = 0

        #max and min ip in binary form
        min = ipBin[0:prefix] + (32-prefix)*'0'
        max = ipBin[0:prefix] + (32-prefix)*'1'

        rmin = ''
        rmax = ''

        #get ip address in dot notation again 
        #convert ip address bin -> dotted
        for i in range:
            if i != 32:
                rmin += str(int(min[temp:i], 2)) + '.'
                rmax += str(int(max[temp:i], 2)) + '.'
                temp = i
            else:
                rmin += str(int(min[temp:i], 2)+1) 
                rmax += str(int(max[temp:i], 2)-1)
        
        return ipaddress.IPv4Address(rmax), ipaddress.IPv4Address(rmin)
    else:
        return None, None
    
# helper function to check if range1 is a subset of range2
def range_subset(range1, range2):
    """Whether range1 is a subset of range2."""
    if not range1:
        return True  # empty range is subset of anything
    if not range2:
        return False  # non-empty range can't be subset of empty range
    if len(range1) > 1 and range1.step % range2.step:
        return False  # must have a single value or integer multiple step
    return range1.start in range2 and range1[-1] in range2

# helper function to load in the appripriate rov database
def load_rov_database(rovset, method):
    # handle rov case 0 - no added rov ASN
    if method == 0:
        print("case 0 - do nothing here")
    # case 1 - add asn from MANRS to the list of ROV covered - high critera
    elif method == 1:
        print("case 1 - adding manrs high")
        with open('/home/ubuntu/manrs-rov-high.txt') as txtfile:
            for line in txtfile:
                rovset.append(str(line))
        rovset = list(dict.fromkeys(rovset))
    # case 2 - check asn against RoVISTA database and mark score > threshold as rov covered
    elif method == 2:
        print("case 2 - adding data from RoVISTA")
        threshold = 0.5
        with open('/home/ubuntu/rovista.txt') as txtfile:
            for line in txtfile:
                rovset.append(str(line))
        rovset = list(dict.fromkeys(rovset))
    # case 3 - add asn from Shulman group
    elif method == 3:
        print("case 3 - adding data from Shulman group")
        with open('/home/ubuntu/protected.txt') as txtfile:
            for line in txtfile:
                rovset.append(str(line))
        rovset = list(dict.fromkeys(rovset))
    # case 4 - add asn from MANRS to the list of ROV covered - low critera
    elif method == 4:
        print("case 4 - adding manrs low")
        with open('/home/ubuntu/manrs-rov-low.txt') as txtfile:
            for line in txtfile:
                rovset.append(str(line))
        rovset = list(dict.fromkeys(rovset))

    return rovset

# helper function to grab the basic information about relays
def calc_relay_stats(consensus_date, rovset):
    # read in consensus and parse guards with bandwidth
    p = '../processed/' + consensus_date + '-processed.pickle'

    # try to open the pickled file  
    try:
        file = open(p, 'rb')
    except FileNotFoundError:
        dates_list = consensus_date.split("-")
        new_hours = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12']
        found = False
        count = 0
        while not found:
            dates_list[-1] = str(new_hours[count])
            new_date = "-".join(dates_list)
            count = count + 1
            p2 = '../processed/' + new_date + '-processed.pickle'
            try:
                file = open(p2, 'rb')
                print('opening replacement date = ', new_date)
                found = True
            except:
                print("not found replacement going next hour")

    # process consensus and collect guard relays info
    rs = pickle.load(file) #list of all relay objects
    WGD = pickle.load(file) #weight in the consensus
    WGG = pickle.load(file) #weight in the consensus
    gs = [r for r in rs if r.is_guard] #get all the guards relay in a list

    numGuardRelays = 0
    numExitRelays = 0
    ASNs = []
    guardASNs = []
    guardWeights = []
    identities = []
    digests = []

    relay_rovs = []
    relay_bws = []
    relay_weights = []
    relay_roas = []
    
    # build guard weights relay and roa/rov coverage
    for r in gs: #iterate through all relays within the guards relays list
        if r.asn is not None:
            asn = int(r.asn)
            ASNs.append(asn)
            if check_rovset(asn, rovset):
                relay_rovs.append(1)
            else:
                relay_rovs.append(0)
        else:
            relay_rovs.append(0)
            ASNs.append(0)

        if r.is_exit:  # if r is an exit
            numExitRelays += 1
            relay_bws.append(r.bw)
            if r.ipv4_roa != None: #the relay has roa 
                w = int(r.bw * WGD)  # wgd, g+e in g position
                relay_roas.append(1)
                identities.append(r.fp)
                digests.append(r.digest)
                relay_weights.append(w)
            else:
                w = int(r.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
                relay_roas.append(0)
                identities.append(r.fp)
                digests.append(r.digest)
                relay_weights.append(w)
        else:
            numGuardRelays += 1
            relay_bws.append(r.bw)
            if r.ipv4_roa != None: #the relay has roa 
                w = int(r.bw * WGG)  # wgg, g in g position
                relay_roas.append(1)
                identities.append(r.fp)
                digests.append(r.digest)
                relay_weights.append(w)
                if r.asn is not None:
                    guardWeights.append(w)
                    guardASNs.append(r.asn)
                else:
                    guardWeights.append(w)
                    guardASNs.append(0)
            else:
                w = int(r.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
                relay_roas.append(0)
                identities.append(r.fp)
                digests.append(r.digest)
                relay_weights.append(w)
                if r.asn is not None:
                    guardWeights.append(w)
                    guardASNs.append(r.asn)
                else:
                    guardWeights.append(w)
                    guardASNs.append(0)

    return relay_rovs, relay_bws, relay_weights, relay_roas,gs, WGG, WGD

# helper function to grab client geographic distribution
def grab_client_geo_dist(consensus_date, countries_last, cweights_last):
    # fetch countries dist on that date
    year = consensus_date.split("-")[0]
    month = consensus_date.split("-")[1]
    date = consensus_date.split("-")[2]
    #print("sanity check here year = " + year + " month = " + month + " date = " + date)
             
    url = "https://metrics.torproject.org/userstats-relay-table.html?start=" + year + "-" + month + "-" + date + "&end=" + year + "-" + month + "-" + date
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "lxml")

    allTds = soup.findAll('td')

    countries = []
    cweights = []


    for t in allTds:
        if "(" not in t.text:
            countries.append(str(t.findChildren()[0]).split("country=")[1][0:2].upper())
        else:
            cweights.append(float(str(t.text).split("(")[1].split("%")[0])/100)
          

    if len(countries) == 0 or len(cweights) == 0:
        print("Tor metrics error! user previous iteration data")
        if len(countries_last) > 0:
            countries = countries_last
            cweights = cweights_last
        else:
            # hard-coded average as backup
            return ["Germany", "United States", "Netherlands", "Ukraine", "Finland", "India", "Lithuania", "Indonesia", "France", "Spain"], [0.5349, 0.1077,0.0360, 0.0313,0.0298,0.0177,0.0164,0.0129,0.0125,0.0118]

    return countries, cweights

# helper function to calculate client roa and rov distribution given geographic distribution
def calc_roa_rov_client(countries, cweights, numIPdict, csvfile, rovset):
    # read in prefix to IP address map
    prefixHosts = get_prefix_addresses_map() # prefix -> number of ip address

    #country -> [list of AS obj] 
    ASdict = dict()
    
    # map all AS by country based on input consensus
    for i in numIPdict: 
        if numIPdict[i].origin not in ASdict.keys():
            ASdict[numIPdict[i].origin] = [numIPdict[i]]
            #country -> [list of AS obj] 

        else:
            ASdict[numIPdict[i].origin].append(numIPdict[i])

    # maintain a dictionary for each category of prefix for each country
    roa_countries = dict()
    rov_countries = dict()
    both_countries = dict()
    neither_countries = dict()
    prefix_count_total = dict()

    # preprocess all ROA information into a list, filter out duplicate and subnetworks
    roa_prefixes = []
    path = "../mergedROAs/" + csvfile
    with open(path) as f1:
        f1.readline()
        for line in f1:
            line = line.split(',')
            try:
                network = line[1]
                # deduplicate here
                if network not in roa_prefixes:
                    roa_prefixes.append(network)
            except:
                pass
    
    # turn all roa prefixes into integer forms
    ip_ranges = [
        (range(int(n.network_address), int(n.broadcast_address)))
        for n in map(ip_network, roa_prefixes)
    ]

    print("Done adding non duplicating roa prefixes")

    # initialize all dictionary counts
    for c in countries:
        prefix_count_total[c] = 0
        rov_countries[c] = 0
        roa_countries[c] = 0
        both_countries[c] = 0
        neither_countries[c] = 0

    # initialize for all other countries
    prefix_count_total["other"] = 0
    rov_countries["other"] = 0
    roa_countries["other"] = 0
    both_countries["other"] = 0
    neither_countries["other"] = 0
   
    time1 = time.time()
    # for every country
    for c in countries:
        ASarray = []
        # grab all ASes fall under that country
        ASList = ASdict[c]
        for asn in ASList:
            ASarray.append(asn)

        # for each AS, grab all its prefixes
        for asn in ASarray:
            asnumber1 = int(asn.ASN)
            prefixes = asn.prefixes

            addedPrefixes = []

            # to speed up , turn all prefixes into integer ranges
            ip_ranges2 = [
                    (range(int(n.network_address), int(n.broadcast_address)))
                    for n in map(ip_network, prefixes)
                ]

            # check for each prefix, if it has roa and rov coverage
            # also check if this prefix is a subprefix of one already counted before, if so ignore
            for i in range(len(prefixes)):
                p3 = prefixes[i]
                rov = False
                roa = False

                # check rov
                if check_rovset(asnumber1, rovset):
                    rov = True
                # check roa - 1 directly against list
                if prefixes[i] in roa_prefixes:
                    roa = True
                # check roa - 2 if a subprefix 
                if roa == False:
                    for q in ip_ranges:
                        if range_subset(ip_ranges2[i], q):
                            roa = True

                # make sure this preefix isn't a subprefix of one previously counted, avoid double counting
                added = False
                for (p,q, w) in addedPrefixes:
                    if range_subset(ip_ranges2[i], p):
                        added = True
                        break
                    if range_subset(p, ip_ranges2[i]):
                        addedPrefixes.remove((p, q, w))
                        if w == "both":
                            both_countries[c] -= q
                        if w == "roa":
                            roa_countries[c] -= q
                        if w == "rov":
                            rov_countries[c] -= q
                        if w == "neither":
                            neither_countries[c] -= q
                
                if roa == True and rov == True and added == False:
                    count = prefixHosts[int(p3.split("/")[1])]
                    both_countries[c] += count
                    addedPrefixes.append((ip_ranges2[i], count, "both"))
                if roa == True and rov == False and added == False:
                    count = prefixHosts[int(p3.split("/")[1])]
                    roa_countries[c] += count
                    addedPrefixes.append((ip_ranges2[i], count, "roa"))
                if roa == False and rov == True and added == False:
                    count = prefixHosts[int(p3.split("/")[1])]
                    rov_countries[c] += count
                    addedPrefixes.append((ip_ranges2[i], count, "rov"))
                if roa == False and rov ==False and added == False:
                    count = prefixHosts[int(p3.split("/")[1])]
                    neither_countries[c] += count
                    addedPrefixes.append((ip_ranges2[i], count, "neither"))
                prefix_count_total[c] += prefixHosts[int(p3.split("/")[1])]
    
    # for every other country
    ASarray_other = []
    # grab all ASes fall under that country
    for key, value in ASdict.items():
        if key not in countries:
            ASList = ASdict[key]
            for asn in ASList:
                ASarray_other.append(asn)

    # for each AS, grab all its prefixes
    for asn in ASarray_other:
        asnumber1 = int(asn.ASN)
        prefixes = asn.prefixes

        addedPrefixes = []

        # to speed up , turn all prefixes into integer ranges
        ip_ranges2 = [
                (range(int(n.network_address), int(n.broadcast_address)))
                for n in map(ip_network, prefixes)
            ]

        # check for each prefix, if it has roa and rov coverage
        # also check if this prefix is a subprefix of one already counted before, if so ignore
        for i in range(len(prefixes)):
            p3 = prefixes[i]
            rov = False
            roa = False

            # check rov
            if check_rovset(asnumber1, rovset):
                rov = True
            # check roa - 1 directly against list
            if prefixes[i] in roa_prefixes:
                roa = True
            # check roa - 2 if a subprefix 
            if roa == False:
                for q in ip_ranges:
                    if range_subset(ip_ranges2[i], q):
                        roa = True

            # make sure this preefix isn't a subprefix of one previously counted, avoid double counting
            added = False
            for (p,q, w) in addedPrefixes:
                if range_subset(ip_ranges2[i], p):
                    added = True
                    break
                if range_subset(p, ip_ranges2[i]):
                    addedPrefixes.remove((p, q, w))
                    if w == "both":
                        both_other -= q
                    if w == "roa":
                        roa_other -= q
                    if w == "rov":
                        rov_other -= q
                    if w == "neither":
                        neither_other -= q
            
            if roa == True and rov == True and added == False:
                count = prefixHosts[int(p3.split("/")[1])]
                both_countries["other"] += count
                addedPrefixes.append((ip_ranges2[i], count, "both"))
            if roa == True and rov == False and added == False:
                count = prefixHosts[int(p3.split("/")[1])]
                roa_countries["other"] += count
                addedPrefixes.append((ip_ranges2[i], count, "roa"))
            if roa == False and rov == True and added == False:
                count = prefixHosts[int(p3.split("/")[1])]
                rov_countries["other"] += count
                addedPrefixes.append((ip_ranges2[i], count, "rov"))
            if roa == False and rov ==False and added == False:
                count = prefixHosts[int(p3.split("/")[1])]
                neither_countries['other'] += count
                addedPrefixes.append((ip_ranges2[i], count, "neither"))
            prefix_count_total["other"] += prefixHosts[int(p3.split("/")[1])]
    time2 = time.time()
    print("what is time 2 - time 1 =", time2 - time1)
    time.sleep(10000000000000)

    # combine both weighted average
    wa_roa = 0
    wa_rov = 0
    wa_both = 0
    wa_neither = 0
    for c in countries:
        wa_roa += cweights[countries.index(c)] * (roa_countries[c]) / prefix_count_total[c]
        wa_rov += cweights[countries.index(c)] * (rov_countries[c]) / prefix_count_total[c]
        wa_both += cweights[countries.index(c)] * (both_countries[c]) / prefix_count_total[c]
        wa_neither += cweights[countries.index(c)] * (neither_countries[c]) / prefix_count_total[c]

    # add in others
    wa_both += (1- sum(cweights)) * both_countries["other"] / prefix_count_total["other"]
    wa_roa += (1-sum(cweights)) * roa_countries["other"] / prefix_count_total["other"]
    wa_rov += (1-sum(cweights)) * rov_countries["other"] / prefix_count_total["other"]
    wa_neither += (1-sum(cweights)) * neither_countries["other"] / prefix_count_total["other"]

    return wa_both, wa_roa, wa_rov, wa_neither

# helper function to calculate client roa and rov distribution for non top 10 country prefixes
def calc_roa_rov_other(countries, cweights, numIPdict, csvfile, rovset):
    # read in prefix to IP address map
    prefixHosts = get_prefix_addresses_map() # prefix -> number of ip address

    #country -> [list of AS obj] 
    ASdict = dict()
    
    # map all AS by country based on input consensus
    for i in numIPdict: 
        if numIPdict[i].origin not in ASdict.keys():
            ASdict[numIPdict[i].origin] = [numIPdict[i]]
            #country -> [list of AS obj] 

        else:
            ASdict[numIPdict[i].origin].append(numIPdict[i])

    
    # maintain a count for all countries
    roa_other = 0
    rov_other = 0
    both_other = 0
    neither_other = 0
    prefix_count_total = 0

    # preprocess all ROA information into a list, filter out duplicate and subnetworks
    roa_prefixes = []
    path = "../mergedROAs/" + csvfile
    with open(path) as f1:
        f1.readline()
        for line in f1:
            line = line.split(',')
            try:
                network = line[1]
                # deduplicate here
                if network not in roa_prefixes:
                    roa_prefixes.append(network)
            except:
                pass
    ip_ranges = [
        (range(int(n.network_address), int(n.broadcast_address)))
        for n in map(ip_network, roa_prefixes)
    ]

    print("Done adding non duplicating roa prefixes in calcing other countries")

    target_countries = []
    for key, value in ASdict.items():
        if key not in countries:
            target_countries.append(key)

    # for every country
    for c in target_countries:
        ASarray = []
        # grab all ASes fall under that country
        ASList = ASdict[c]
        for asn in ASList:
            ASarray.append(asn.ASN)

        # for each AS, grab all its prefixes
        for asn in ASList:
            asnumber1 = int(asn.ASN)
            prefixes = asn.prefixes

            addedPrefixes = []

            # to speed up , turn all prefixes into integer ranges
            ip_ranges2 = [
                    (range(int(n.network_address), int(n.broadcast_address)))
                    for n in map(ip_network, prefixes)
                ]

            # check for each prefix, if it has roa and rov coverage
            # also check if this prefix is a subprefix of one already counted before, if so ignore
            for i in range(len(prefixes)):
                p3 = prefixes[i]
                rov = False
                roa = False

                # check rov
                if check_rovset(asnumber1, rovset):
                    rov = True
                # check roa - 1 directly against list
                if prefixes[i] in roa_prefixes:
                    roa = True
                # check roa - 2 if a subprefix 
                if roa == False:
                    for q in ip_ranges:
                        if range_subset(ip_ranges2[i], q):
                            roa = True

                # make sure this preefix isn't a subprefix of one previously counted, avoid double counting
                added = False
                for (p,q, w) in addedPrefixes:
                    if range_subset(ip_ranges2[i], p):
                        added = True
                        break
                    if range_subset(p, ip_ranges2[i]):
                        addedPrefixes.remove((p, q, w))
                        if w == "both":
                            both_other -= q
                        if w == "roa":
                            roa_other -= q
                        if w == "rov":
                            rov_other -= q
                        if w == "neither":
                            neither_other -= q
                
                if roa == True and rov == True and added == False:
                    count = prefixHosts[int(p3.split("/")[1])]
                    both_other += count
                    addedPrefixes.append((ip_ranges2[i], count, "both"))
                if roa == True and rov == False and added == False:
                    count = prefixHosts[int(p3.split("/")[1])]
                    roa_other += count
                    addedPrefixes.append((ip_ranges2[i], count, "roa"))
                if roa == False and rov == True and added == False:
                    count = prefixHosts[int(p3.split("/")[1])]
                    rov_other += count
                    addedPrefixes.append((ip_ranges2[i], count, "rov"))
                if roa == False and rov ==False and added == False:
                    count = prefixHosts[int(p3.split("/")[1])]
                    neither_other += count
                    addedPrefixes.append((ip_ranges2[i], count, "neither"))
                prefix_count_total += prefixHosts[int(p3.split("/")[1])]
    
    #print("Done iterating through prefixes, before count")

    # calculate weighted average
    wa_roa = 0
    wa_rov = 0
    wa_both = 0
    wa_neither = 0
   
    wa_roa = roa_other / prefix_count_total
    wa_rov = rov_other / prefix_count_total
    wa_both = both_other / prefix_count_total
    wa_neither = neither_other / prefix_count_total  

    return wa_both, wa_roa, wa_rov, wa_neither, prefix_count_total


# helper function for one iteration of pre-matching guard relays with clients
def matching_pre(bws, gs, clients_both, clients_roa, clients_rov, clients_neither, relayWeights, WGG, WGD, rovset):
    # count pre matching results
    matched = 0

    weights2 = relayWeights

    average_bw = sum(bws) / len(bws)

    dynamic_guards = {}
    for g in gs:
        dynamic_guards[g] = 0

    for client in clients_both:
        # get client coverage info
        chosenGuard = random.choices(gs, weights = weights2, k=1)[0]
        dynamic_guards[chosenGuard] += 1

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay from selection")
            weights2[gs.index(chosenGuard)] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ) or ((check_rovset(chosenGuard.asn, rovset))  and client.roaCovered == True):
                matched += 1
        except:
            pass

    for client in clients_roa:
        # get client coverage info
        chosenGuard = random.choices(gs, weights = weights2, k=1)[0]
        dynamic_guards[chosenGuard] += 1

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay from selection")
            weights2[gs.index(chosenGuard)] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ) or ((check_rovset(chosenGuard.asn, rovset))  and client.roaCovered == True):
                matched += 1
        except:
            pass
    for client in clients_rov:
        # get client coverage info
        chosenGuard = random.choices(gs, weights = weights2, k=1)[0]
        dynamic_guards[chosenGuard] += 1

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay from selection")
            weights2[gs.index(chosenGuard)] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ) or ((check_rovset(chosenGuard.asn, rovset))  and client.roaCovered == True):
                matched += 1
        except:
            pass
    for client in clients_neither:
        # get client coverage info
        chosenGuard = random.choices(gs, weights = weights2, k=1)[0]
        dynamic_guards[chosenGuard] += 1

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay from selection")
            weights2[gs.index(chosenGuard)] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ) or ((check_rovset(chosenGuard.asn, rovset))  and client.roaCovered == True):
                matched += 1
        except:
            pass
        
    #print("Done guard selection before optimization - first attempt before optimization")
    #print("===========================================================")

    return matched


# helper function for one iteration of pre-matching guard relays with clients
def matching_pre_new(bws, gs, clients_both, clients_roa, clients_rov, clients_neither, relayWeights, WGG, WGD, rovset):
    # count pre matching results
    matched = 0

    weights2 = relayWeights

    average_bw = sum(bws) / len(bws)

    dynamic_guards = {}
    for g in gs:
        dynamic_guards[g] = 0

    for client in clients_both:
        # get client coverage info
        chosenGuard = random.choices(gs, weights = weights2, k=1)[0]
        if client.matchedRelay is not None and client.matchedRelay in gs:
            chosenGuard = client.matchedRelay

        dynamic_guards[chosenGuard] += 1

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay from selection")
            weights2[gs.index(chosenGuard)] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ) or ((check_rovset(chosenGuard.asn, rovset))  and client.roaCovered == True):
                matched += 1
        except:
            pass

    for client in clients_roa:
        # get client coverage info
        chosenGuard = random.choices(gs, weights = weights2, k=1)[0]
        if client.matchedRelay is not None and client.matchedRelay in gs:
            chosenGuard = client.matchedRelay
        dynamic_guards[chosenGuard] += 1

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay from selection")
            weights2[gs.index(chosenGuard)] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ) or ((check_rovset(chosenGuard.asn, rovset))  and client.roaCovered == True):
                matched += 1
        except:
            pass
    for client in clients_rov:
        # get client coverage info
        chosenGuard = random.choices(gs, weights = weights2, k=1)[0]
        if client.matchedRelay is not None and client.matchedRelay in gs:
            chosenGuard = client.matchedRelay
        dynamic_guards[chosenGuard] += 1

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay from selection")
            weights2[gs.index(chosenGuard)] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ) or ((check_rovset(chosenGuard.asn, rovset))  and client.roaCovered == True):
                matched += 1
        except:
            pass
    for client in clients_neither:
        # get client coverage info
        chosenGuard = random.choices(gs, weights = weights2, k=1)[0]
        if client.matchedRelay is not None and client.matchedRelay in gs:
            chosenGuard = client.matchedRelay
        dynamic_guards[chosenGuard] += 1

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay from selection")
            weights2[gs.index(chosenGuard)] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ) or ((check_rovset(chosenGuard.asn, rovset))  and client.roaCovered == True):
                matched += 1
        except:
            pass
        
    #print("Done guard selection before optimization - first attempt before optimization")
    #print("===========================================================")

    return matched


# helper function for one iteration of post-matching guard relays with clients
def matching_post(consensus_date, clients_both, clients_roa, clients_rov, clients_neither, relayWeights, relay_roas, relay_rovs, client_dist, gs, WGG, WGD, rovset, saveclients):
    # optimization using linear program
    matched2 = 0

    average_bw = sum(relayWeights) / len(relayWeights)

    croas_both = []
    crovs_both = []
    for client in clients_both:
        croas_both.append(1)
        crovs_both.append(1)

    croas_roa = []
    crovs_roa = []
    for client in clients_roa:
        croas_roa.append(1)
        crovs_roa.append(0)

    croas_rov = []
    crovs_rov = []
    for client in clients_rov:
        croas_rov.append(0)
        crovs_rov.append(1)

    croas_neither = []
    crovs_neither = []
    for client in clients_neither:
        croas_neither.append(0)
        crovs_neither.append(0)

    start_time2 = time.time()
    optimized_weights = lp_optimization(relayWeights, relay_roas, relay_rovs, croas_both, crovs_both, croas_roa, crovs_roa, croas_rov, crovs_rov, croas_neither, crovs_neither, client_dist)
    # quick check to remove any negative results resulting from rounding
    for i in range(len(optimized_weights)):
        if optimized_weights[i] < 0:
            optimized_weights[i] = 0

    end_time2 = time.time()

    #print("lp time = ",end_time2 - start_time2)

    optimized_weights1 = optimized_weights[0:len(relay_roas)]
    optimized_weights2 = optimized_weights[len(relay_roas):2*len(relay_roas)]
    optimized_weights3 = optimized_weights[2*len(relay_roas): 3*len(relay_roas)]
    optimized_weights4 = optimized_weights[3*len(relay_roas): 4*len(relay_roas)]
        
    utilization = 0
    load = 0.8

    for i in range(len(relay_roas)):
        inde = i // len(relay_roas) # group number
        r = i % len(relay_roas) # relay number with in the group
        p = client_dist[0] * optimized_weights1[r] + client_dist[1] * optimized_weights2[r] + client_dist[2] * optimized_weights3[r] + client_dist[3] * optimized_weights4[r]
        utilization += p * sum(relayWeights) * load

    ut_perc = utilization/sum(relayWeights)
    # print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("utilizaiton = ", ut_perc)          

    dynamic_guards = {}
    for g in gs:
        dynamic_guards[g] = 0
    chosenGuards1 = []

    for client in clients_both:
        # get client coverage info
        i = random.choices(range(len(optimized_weights1)), weights = optimized_weights1, k=1)[0]
        chosenGuard = gs[i]
        chosenGuards1.append(i)
        dynamic_guards[chosenGuard] += 1
        client.matchedRelay = chosenGuard

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay" + str(i) + " from selection")
            optimized_weights1[i] = 0

        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ):
                matched2 += 1
                # print("chosen guard asn = ", chosenGuard.asn)
            if ((check_rovset(chosenGuard.asn, rovset)) and client.roaCovered == True):
                matched2 += 1
        except:
            pass
            
    chosenGuards2 = []
    for client in clients_roa:
        # get client coverage info
        i = random.choices(range(len(optimized_weights2)), weights = optimized_weights2, k=1)[0]
        chosenGuard = gs[i]
        chosenGuards2.append(i)
        dynamic_guards[chosenGuard] += 1
        client.matchedRelay = chosenGuard

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay" + str(i) + " from selection")
            optimized_weights2[i] = 0

        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ):
                matched2 += 1
                # print("chosen guard asn = ", chosenGuard.asn)
            if ((check_rovset(chosenGuard.asn, rovset)) and client.roaCovered == True):
                matched2 += 1
        except:
            pass
    

    chosenGuards3 = []

    for client in clients_rov:
        # get client coverage info
        i = random.choices(range(len(optimized_weights3)), weights = optimized_weights3, k=1)[0]
        chosenGuard = gs[i]
        chosenGuards3.append(i)
        dynamic_guards[chosenGuard] += 1
        client.matchedRelay = chosenGuard
        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay" + str(i) + " from selection")
            optimized_weights3[i] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ):
                matched2 += 1
                # print("chosen guard asn = ", chosenGuard.asn)
            if ((check_rovset(chosenGuard.asn, rovset)) and client.roaCovered == True):
                matched2 += 1
        except:
            pass
    
    
    chosenGuards4 = []

    for client in clients_neither:
        # get client coverage info
        i = random.choices(range(len(optimized_weights4)), weights = optimized_weights4, k=1)[0]
        chosenGuard = gs[i]
        chosenGuards4.append(i)
        dynamic_guards[chosenGuard] += 1
        client.matchedRelay = chosenGuard
        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if w/dynamic_guards[chosenGuard] <= average_bw:
            #print("hitting threshold, remove relay" + str(i) + " from selection")
            optimized_weights4[i] = 0
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ):
                matched2 += 1
                # print("chosen guard asn = ", chosenGuard.asn)
            if ((check_rovset(chosenGuard.asn, rovset)) and client.roaCovered == True):
                matched2 += 1
        except:
            pass

        #print("Done guard selection after optimization - second attempt after optimization")
        #print("===========================================================")

    # add all clients after matching into list
    resultClientList = []
    for client in clients_roa:
        resultClientList.append(client)

    for client in clients_rov:
        resultClientList.append(client)

    for client in clients_both:
        resultClientList.append(client)

    for client in clients_neither:
        resultClientList.append(client)

    if saveclients:
        next_date = get_next_date(consensus_date)
        with open("../clients_daily/1000000TorClients-" + next_date + ".pickle", 'wb') as f:
            pickle.dump(resultClientList, f)
   
    return matched2


# helper function for one iteration of post-matching guard relays with clients
def matching_post_new(consensus_date, clients_both, clients_roa, clients_rov, clients_neither, relayWeights, relay_roas, relay_rovs, client_dist, gs, WGG, WGD, rovset):
    # optimization using linear program
    matched2 = 0

    average_bw = sum(relayWeights) / 1000000

    croas_both = []
    crovs_both = []
    for client in clients_both:
        croas_both.append(1)
        crovs_both.append(1)

    croas_roa = []
    crovs_roa = []
    for client in clients_roa:
        croas_roa.append(1)
        crovs_roa.append(0)

    croas_rov = []
    crovs_rov = []
    for client in clients_rov:
        croas_rov.append(0)
        crovs_rov.append(1)

    croas_neither = []
    crovs_neither = []
    for client in clients_neither:
        croas_neither.append(0)
        crovs_neither.append(0)

    start_time2 = time.time()
    optimized_weights = lp_optimization(relayWeights, relay_roas, relay_rovs, croas_both, crovs_both, croas_roa, crovs_roa, croas_rov, crovs_rov, croas_neither, crovs_neither, client_dist)

    end_time2 = time.time( relng_ay)

    #print("lp time = ",end_time2 - start_time2)

    optimized_weights1 = optimized_weights[0:len(relay_roas)]
    optimized_weights2 = optimized_weights[len(relay_roas):2*len(relay_roas)]
    optimized_weights3 = optimized_weights[2*len(relay_roas): 3*len(relay_roas)]
    optimized_weights4 = optimized_weights[3*len(relay_roas): 4*len(relay_roas)]

    weighted_average_after = 0
    for i in range(len(optimized_weights1)):
        p = optimized_weights1[i] / sum(optimized_weights1)
        weighted_average_after += p * relayWeights[i]

    for i in range(len(optimized_weights2)):
        p = optimized_weights2[i] / sum(optimized_weights2)
        weighted_average_after += p * relayWeights[i]

    for i in range(len(optimized_weights3)):
        p = optimized_weights3[i] / sum(optimized_weights3)
        weighted_average_after += p * relayWeights[i]

    for i in range(len(optimized_weights4)):
        p = optimized_weights4[i] / sum(optimized_weights4)
        weighted_average_after += p * relayWeights[i]

    weighted_average_after = weighted_average_after / 4
    print("what is weighted average after = ", weighted_average_after)

    # # quick sanity check to remove any negative results resulting from rounding
    # # https://github.com/scipopt/PySCIPOpt/issues/313
    for i in range(len(optimized_weights1)):
        if optimized_weights1[i] < 0:
            optimized_weights1[i] = 0
        optimized_weights1[i] = optimized_weights1[i] * 1000000000000000

    # optimized_weights1_save = copy.deepcopy(optimized_weights1)

    # for i in range(len(optimized_weights1)):
    #     optimized_weights1[i] = optimized_weights1_save[i] / sum(optimized_weights1_save)
    
    for i in range(len(optimized_weights2)):
        if optimized_weights2[i] < 0:
            optimized_weights2[i] = 0
        optimized_weights2[i] = optimized_weights2[i] * 1000000000000000

    # optimized_weights2_save = copy.deepcopy(optimized_weights2)

    # for i in range(len(optimized_weights2)):
    #     optimized_weights2[i] = optimized_weights2_save[i] / sum(optimized_weights2_save)

    for i in range(len(optimized_weights3)):
        if optimized_weights3[i] < 0:
            optimized_weights3[i] = 0
        optimized_weights3[i] = optimized_weights3[i] * 1000000000000000

    # optimized_weights3_save = copy.deepcopy(optimized_weights3)

    # for i in range(len(optimized_weights3)):
    #     optimized_weights3[i] = optimized_weights3_save[i] / sum(optimized_weights3_save)

    for i in range(len(optimized_weights4)):
        if optimized_weights4[i] < 0:
            optimized_weights4[i] = 0
        optimized_weights4[i] = optimized_weights4[i] * 1000000000000000

    # optimized_weights4_save = copy.deepcopy(optimized_weights4)

    # for i in range(len(optimized_weights4)):
    #     optimized_weights4[i] = optimized_weights4_save[i] / sum(optimized_weights4_save)

        
    utilization = 0
    load = 0.8

    for i in range(len(relay_roas)):
        inde = i // len(relay_roas) # group number
        r = i % len(relay_roas) # relay number with in the group
        p = client_dist[0] * optimized_weights1[r] + client_dist[1] * optimized_weights2[r] + client_dist[2] * optimized_weights3[r] + client_dist[3] * optimized_weights4[r]
        utilization += p * sum(relayWeights) * load

    ut_perc = utilization/sum(relayWeights)
    # print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    # print("sanity check optimized1 = ", sum(optimized_weights1))
    # print("sanity check optimized2 = ", sum(optimized_weights2))
    # print("sanity check optimized3 = ", sum(optimized_weights3))
    # print("sanity check optimized4 = ", sum(optimized_weights4))

    dynamic_guards = {}
    for g in gs:
        dynamic_guards[g] = 0
    chosenGuards1 = []

    for client in clients_both:
        # get client coverage info
        # print("what is optimized_weights1 = ", optimized_weights1)
        i = random.choices(list(range(len(optimized_weights1))), weights = optimized_weights1, k=1)[0]
        # a = np.array(range(len(optimized_weights1)))
        # i = np.random.choice(a,p=optimized_weights1)
        chosenGuard = gs[i]
        if client.matchedRelay is not None and client.matchedRelay in gs:
            chosenGuard = client.matchedRelay
        chosenGuards1.append(i)
        dynamic_guards[chosenGuard] += 1
        client.matchedRelay = chosenGuard

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if chosenGuard.bw/dynamic_guards[chosenGuard] <= average_bw and optimized_weights1[i] * (chosenGuard.bw/dynamic_guards[chosenGuard]) / average_bw > 0:
            #print("hitting threshold, remove relay" + str(i) + " from selection")
            optimized_weights1[i] = optimized_weights1[i] * (chosenGuard.bw/dynamic_guards[chosenGuard]) / average_bw

        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ):
                matched2 += 1
                # print("chosen guard asn = ", chosenGuard.asn)
            if ((check_rovset(chosenGuard.asn, rovset)) and client.roaCovered == True):
                matched2 += 1
        except:
            pass

            
    chosenGuards2 = []
    for client in clients_roa:
        # get client coverage info
        i = random.choices(list(range(len(optimized_weights2))), weights = optimized_weights2, k=1)[0]
        # a = np.array(range(len(optimized_weights2)))
        # i = np.random.choice(a,p=optimized_weights2)
        chosenGuard = gs[i]
        if client.matchedRelay is not None and client.matchedRelay in gs:
            chosenGuard = client.matchedRelay
        chosenGuards2.append(i)
        dynamic_guards[chosenGuard] += 1
        client.matchedRelay = chosenGuard

        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if chosenGuard.bw/dynamic_guards[chosenGuard] <= average_bw and optimized_weights2[i] * (chosenGuard.bw/dynamic_guards[chosenGuard]) / average_bw > 0:
            #print("hitting threshold, remove relay" + str(i) + " from selection")
            optimized_weights2[i] = optimized_weights2[i] * (chosenGuard.bw/dynamic_guards[chosenGuard]) / average_bw

        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ):
                matched2 += 1
                # print("chosen guard asn = ", chosenGuard.asn)
            if ((check_rovset(chosenGuard.asn, rovset)) and client.roaCovered == True):
                matched2 += 1
        except:
            pass
    

    chosenGuards3 = []

    for client in clients_rov:
        # get client coverage info
        i = random.choices(list(range(len(optimized_weights3))), weights = optimized_weights3, k=1)[0]
        # a = np.array(range(len(optimized_weights3)))
        # i = np.random.choice(a,p=optimized_weights3)
        chosenGuard = gs[i]
        if client.matchedRelay is not None and client.matchedRelay in gs:
            chosenGuard = client.matchedRelay
        chosenGuards3.append(i)
        dynamic_guards[chosenGuard] += 1
        client.matchedRelay = chosenGuard
        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if chosenGuard.bw/dynamic_guards[chosenGuard] <= average_bw and optimized_weights3[i] * (chosenGuard.bw/dynamic_guards[chosenGuard]) / average_bw > 0:
            #print("hitting threshold, remove relay" + str(i) + " from selection")
            optimized_weights3[i] = optimized_weights3[i] * (chosenGuard.bw/dynamic_guards[chosenGuard]) / average_bw
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ):
                matched2 += 1
                # print("chosen guard asn = ", chosenGuard.asn)
            if ((check_rovset(chosenGuard.asn, rovset)) and client.roaCovered == True):
                matched2 += 1
        except:
            pass
    
    
    chosenGuards4 = []

    for client in clients_neither:
        # get client coverage info
        i = random.choices(list(range(len(optimized_weights4))), weights = optimized_weights4, k=1)[0]
        # a = np.array(range(len(optimized_weights4)))
        # i = np.random.choice(a,p=optimized_weights4)
        chosenGuard = gs[i]
        if client.matchedRelay is not None and client.matchedRelay in gs:
            chosenGuard = client.matchedRelay
        chosenGuards4.append(i)
        dynamic_guards[chosenGuard] += 1
        client.matchedRelay = chosenGuard
        if chosenGuard.is_exit:  # if r is an exit
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
            else:
                w = int(chosenGuard.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
        else:
            if chosenGuard.ipv4_roa != None: #the relay has roa 
                w = int(chosenGuard.bw * WGG)  # wgg, g in g position
            else:
                w = int(chosenGuard.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

        if chosenGuard.bw/dynamic_guards[chosenGuard] <= average_bw and optimized_weights4[i] * (chosenGuard.bw/dynamic_guards[chosenGuard]) / average_bw > 0:
            #print("hitting threshold, remove relay" + str(i) + " from selection")
            optimized_weights4[i] = optimized_weights4[i] * (chosenGuard.bw/dynamic_guards[chosenGuard]) / average_bw
        # compute matched
        try:
            if (chosenGuard.ipv4_roa != None and (client.rovCovered == True) ):
                matched2 += 1
                # print("chosen guard asn = ", chosenGuard.asn)
            if ((check_rovset(chosenGuard.asn, rovset)) and client.roaCovered == True):
                matched2 += 1
        except:
            pass

        #print("Done guard selection after optimization - second attempt after optimization")
        #print("===========================================================")

    # add all clients after matching into list
    resultClientList = []
    for client in clients_roa:
        resultClientList.append(client)

    for client in clients_rov:
        resultClientList.append(client)

    for client in clients_both:
        resultClientList.append(client)

    for client in clients_neither:
        resultClientList.append(client)

    # write all client objects along with their selection into file
    next_date = get_next_date(consensus_date)
    with open("../clients_daily/1000000TorClients-" + next_date + ".pickle", 'wb') as f:
        pickle.dump(resultClientList, f)

    
    return matched2


# main function for generating users and choosing guards
def user_specified_client2(consensus_date, numClients, csvfile, numIPdict, rovset, wa_both_save, wa_roa_save, wa_rov_save, wa_neither_save, countries_save, cweights_save, gen_clients = False, method = 0):
    '''
    primary function used to make customized client objects based the provided roa, rov coverage.
    This function makes a client object, assign country, ASN, ip address, check to see if the coverage category still need this kind of client, if in need append to the result list else discard the client and start over again. 
    Because the function randomly assigns country, ASN, etc and the roa coverage stems from these info. We cannot specify in making a client having certain coverage. So we just keep making new client until every coverage category has been fulfilled.
    The resulting list could be pickled for future use, so each run of simulation is using the same client list, thus the same roa,rov coverage situation.

    :param consensus_date: (string) the consensus file used, e.g. 2021-01-01-00
    :param numClients: (int) total number of clients in the result list based on the above weights 
    :param csvfile: (string) filename to .csv file containing ROA information to check for roa coverage 
    
    :return: (list) list of clients generated and the count for each coverage type (ROA, ROV, ROA_ROV, neither)
    
    '''

    # merged step - generate clients and guard at the same time

    #pull in country data as global variable 
    resultClientList = []

    rovset = load_rov_database(rovset, method)

    start_time0 = time.time()
    relay_rovs, relay_bws, relay_weights, relay_roas, gs, WGG, WGD = calc_relay_stats(consensus_date, rovset)
    end_time0 = time.time()
    print("calc relay stats took = " + str(end_time0 - start_time0) + "s")

    start_time1 = time.time()
    countries, cweights = grab_client_geo_dist(consensus_date, countries_save, cweights_save)
    wa_both, wa_roa, wa_rov, wa_neither = calc_roa_rov_client(countries, cweights, numIPdict, csvfile, rovset)
    end_time1 = time.time()
    print("calc client roa rov distribution took = " + str(end_time1 - start_time1) +  " s") 


    status_list = ['roa', 'rov', 'both', 'neither']
    status_weight = [wa_roa, wa_rov, wa_both, wa_neither]

    #current number of clients for each category 
    croa = 0
    crov = 0
    croa_rov = 0
    cneither = 0
    clients_roa = []
    clients_rov = []
    clients_both = []
    clients_neither = []

    
    # if first day, we generate all clients according to distribution and then perform optimization
    if gen_clients:
        for i in range(numClients):

            st = random.choices(status_list, weights = status_weight, k = 1)[0]

            newClient = Client("matching")

            if st == 'roa':
                croa += 1
                newClient.roaCovered = True
                newClient.rovCovered = False
                clients_roa.append(newClient)
            elif st == 'rov':
                crov += 1
                newClient.roaCovered = False
                newClient.rovCovered = True
                clients_rov.append(newClient)
            elif st == 'both':
                croa_rov += 1
                newClient.roaCovered = True
                newClient.rovCovered = True
                clients_both.append(newClient)
            else:
                cneither += 1
                newClient.roaCovered = False
                newClient.rovCovered = False
                clients_neither.append(newClient)

        # perform optimization here
        print("Done generating clients lists")
        print("===========================================================")

        # compute actual roa rov distribution of clients
        client_dist = []
        sum_num_clients = len(clients_both) + len(clients_roa) + len(clients_rov) + len(clients_neither)
        client_dist.append(len(clients_both)/sum_num_clients)
        client_dist.append(len(clients_roa)/sum_num_clients)
        client_dist.append(len(clients_rov)/sum_num_clients)
        client_dist.append(len(clients_neither)/sum_num_clients)

        print("Start guard selection")

        consensus_date2 = consensus_date.split('-')
        
        t  = datetime(int(consensus_date2[0]),int(consensus_date2[1]),int(consensus_date2[2]),int(consensus_date2[3]))

        save_clients = True

        matched_num_post = matching_post(consensus_date, clients_both, clients_roa, clients_rov, clients_neither, relay_bws, relay_roas, relay_rovs, client_dist, gs, WGG, WGD, rovset, save_clients)
    
        matched = matched_num_post / sum_num_clients

        return matched, wa_both, wa_roa, wa_rov, wa_neither, countries, cweights

    else:
        print("loading clients directly from pickle and update based on new geoclient distribution")
        y = consensus_date.split("-")[0]
        m = consensus_date.split("-")[1]
        d = consensus_date.split("-")[2]
        new_date = y + "-" + m + "-" + d
        file = open("../clients_daily/1000000TorClients-" + new_date + ".pickle", 'rb')
        resultClientList = pickle.load(file)

        # # compare the difference to arrive at the delta clients
        # countries, cweights = grab_client_geo_dist(consensus_date, countries_save, cweights_save)
        # wa_both, wa_roa, wa_rov, wa_neither = calc_roa_rov_client(countries, cweights, numIPdict, csvfile, rovset)

        # wa_both += (1- sum(cweights)) * both_other
        # wa_roa += (1-sum(cweights)) * roa_other
        # wa_rov += (1-sum(cweights)) * rov_other
        # wa_neither += (1-sum(cweights)) * neither_other

        diff1 = wa_both - wa_both_save
        diff2 = wa_roa - wa_roa_save
        diff3 = wa_rov - wa_rov_save
        diff4 = wa_neither - wa_neither_save

        clients_roa = []
        clients_rov = []
        clients_both = []
        clients_neither = []

        for c in resultClientList:
            if c.roaCovered == True and c.rovCovered == True:
                clients_both.append(c)
            if c.roaCovered == True and c.rovCovered == False:
                clients_roa.append(c)
            if c.roaCovered == False and c.rovCovered == True:
                clients_rov.append(c)
            if c.roaCovered == False and c.rovCovered == False:
                clients_neither.append(c)       

        croa = len(clients_roa)
        crov = len(clients_rov)
        croa_rov = len(clients_both)
        cneither = len(clients_neither)
        
        # if new wa is greater than old wa, then we add clients
        if diff1 >= 0:
            num = round(diff1 * numClients)
            for i in range(0, num):
                newClient = Client("matching")
                croa_rov += 1
                newClient.roaCovered = True
                newClient.rovCovered = True
                clients_both.append(newClient)
        if diff2 >= 0:
            num = round(diff2 * numClients)
            for i in range(0, num):
                newClient = Client("matching")
                croa += 1
                newClient.roaCovered = True
                newClient.rovCovered = False
                clients_roa.append(newClient)
        if diff3 >= 0:
            num = round(diff3 * numClients)
            for i in range(0, num):
                newClient = Client("matching")
                crov += 1
                newClient.roaCovered = False
                newClient.rovCovered = True
                clients_rov.append(newClient)
        if diff4 >= 0:
            num = round(diff4 * numClients)
            for i in range(0, num):
                newClient = Client("matching")
                cneither += 1
                newClient.roaCovered = False
                newClient.rovCovered = False
                clients_neither.append(newClient)

        # if new wa is smaller than old wa, then we kick clients
        if diff1 < 0:
            num = round(diff1 * numClients)
            for i in range(0, num):
                croa_rov -= 1
                clients_both.pop()
        if diff2 < 0:
            num = round(diff2 * numClients)
            for i in range(0, num):
                croa -= 1
                clients_roa.pop()
        if diff3 < 0:
            num = round(diff3 * numClients)
            for i in range(0, num):
                crov -= 1
                clients_rov.pop()
        if diff4 < 0:
            num = round(diff4 * numClients)
            for i in range(0, num):
                cneither -= 1
                clients_neither.pop()

        # perform optimization here
        print("Done modifying clients lists")
        print("===========================================================")

        # compute actual roa rov distribution of clients
        client_dist = []
        sum_num_clients = len(clients_both) + len(clients_roa) + len(clients_rov) + len(clients_neither)
        client_dist.append(len(clients_both)/sum_num_clients)
        client_dist.append(len(clients_roa)/sum_num_clients)
        client_dist.append(len(clients_rov)/sum_num_clients)
        client_dist.append(len(clients_neither)/sum_num_clients)

        print("Start guard selection")

        consensus_date2 = consensus_date.split('-')
        
        t  = datetime(int(consensus_date2[0]),int(consensus_date2[1]),int(consensus_date2[2]),int(consensus_date2[3]))

        matched_num_post = matching_post_new(consensus_date, clients_both, clients_roa, clients_rov, clients_neither, relay_bws, relay_roas, relay_rovs, client_dist, gs, WGG, WGD, rovset)

        matched2 = matched_num_post / sum_num_clients
        
        return matched2, wa_both, wa_roa, wa_rov, wa_neither, countries, cweights


def graph_ROACoverage(h, p_roa, make_pickle = True,make_graph = True, name = "0.5ROACoverage2023.png"):
    """
    graph and pickle the ROA coverage stats for a consensus file after running the simulation 
    :param p_roa: result from the guard_sim main function, input the same vairbale into this function to make graph and pickle file 
    :param make_pickle: (boolean) whether to make pickle of the load balance data 
    :param make_graph: (boolean) whether to make graph of Load Balance, save to current directory 
    :param name: (string) name of the graph is make_graph = True
    """
    if make_graph:
        x = range(len(h))
        for d in p_roa:
            d = d *100
        plt.xlabel('Date')
        plt.ylabel('Client Coverage %')
        plt.title('Percent of Clients with ROA Covered Guard')
        plt.plot(x,p_roa,marker = 'o')
        plt.xticks(x, h, rotation ='vertical')
        plt.savefig(name)

# map ASN to prefix and num of IP
def getAllAS3(routeviewFile):
    """
    using routeview data, create dictionary ASn -> ASN object. ASN object has the AS' prefixes and total number of IP addresses. 

    :param routeviewFile: (string) file path to the routeview data 
    """
    #get the prefix -> num of ip addresses map 
    prefix_hosts_map = get_prefix_addresses_map()

    #dictionary for storing result, ASN -> ASN object 
    ASDict = dict() 

    #open the route view data
    #IP address -> ASN map 
    #https://www.caida.org/catalog/datasets/routeviews-prefix2as/#H2838
    with open(routeviewFile) as tsv:
        #retrieve the tab separated data 
        for line in csv.reader(tsv, dialect = "excel-tab"):
            
            #get the max and min of the current ip prefix 
            cmax, cmin = get_max_min(line[0] + '/' + line[1])

            #check to see if prefix is 32, b/c 32 does not have any addresses
            if cmax != None and cmin != None:

                #account for multi-origin prefix 
                ASNList = re.split(',|_' ,line[2])      

                for cASN in ASNList:
                    
                    #create new entry in dict if ASN does not exist, also assign numIPv4 and prevmax 
                    if cASN not in ASDict.keys():
                        ASDict[cASN] = AS( ASN = cASN)
                        ASDict[cASN].prevMax = cmax
                        ASDict[cASN].numIPv4 =  prefix_hosts_map[int(line[1])]
                        ASDict[cASN].prefixes.append(line[0] + '/' + line[1])
                    #compare with the prevMax address to avoid double counting. some entries are just more specific than previous entries 
                    if cmin > ASDict[cASN].prevMax:
                        #if the prev entry doesnt contain current entry, add the num of hosts into the numIPv4 field 
                        ASDict[cASN].numIPv4 +=  prefix_hosts_map[int(line[1])]
            else:
                continue


    return ASDict

# map orgnization ID to origin/ASN
def preprocess_asn_origin(caidaFile):
    
    """
    preprocess the caida data to assign origin to ASN. 
    map orginzation id to origin country
    https://www.caida.org/catalog/datasets/as-organizations/

    :param caidaFile: (string) path to the Caida file 

    :return: (dictionary) 2 dictionary that when used together could find the origin of an AS using ASN 
    """
    orgID_origin = dict() #maps orgID -> origin 

    asn_orgID  =dict() #maps ASN -> orgID 
    
    with open(caidaFile) as f1:
        for line in f1:
            if not (line.startswith("#")):
                tempList = line.split('|')
               
                if '-' in tempList[0]:
                    orgID_origin[tempList[0]] = tempList[-2]
                else:
                    asn_orgID[tempList[0]] = tempList[3]
    return asn_orgID, orgID_origin

# include origin in ASN->IP 
def get_origin(asn_orgID, orgID_origin, ASNnumIP):
    """
    assign origin to all ASes after tallying up the number of IP addresses announced 

    :param asn_orgID: (dictionary) helper dict obtained from preprocess_asn_origin(caidaFile)
    :param orgID_origin: (dictionary) helper dict obtained from preprocess_asn_origin(caidaFile)
    :param ASNnumIP: (dictionary) result dict of all AS with number of Ip addresses tallied up using getAllAS3()

    :return: (dictionary) return ASNnumIP dict with the origin of each AS filled in 
    """
    for asn in ASNnumIP.keys():
        try:
            ASNnumIP[asn].origin = orgID_origin[asn_orgID[asn]]
        except KeyError:
            ASNnumIP[asn].origin = 'NA'
        # print(ASNnumIP[asn].origin)
    return ASNnumIP


# helper function to plot results
def plot_result():
    CB_color_cycle = ['#377eb8', '#ff7f00', '#4daf4a',
                    '#f781bf', '#a65628', '#984ea3',
                    '#999999', '#e41a1c', '#dede00']

    df = pd.read_csv("./output-matching-202305.csv")
    
    res = df.groupby(['date', 'case'])['matched_before'].mean().reset_index()
    res = df.groupby(['date', 'case'], as_index=False)['matched_before'].mean()

    res2 = df.groupby(['date', 'case'])['matched_after'].mean().reset_index()
    res2 = df.groupby(['date', 'case'], as_index=False)['matched_after'].mean()

    before1 = res.loc[res['case'] == "no added rov"]
    before3 = res.loc[res['case'] == "manrs-high"]
    before2 = res.loc[res['case'] == "RoVISTA"]
    before4 = res.loc[res['case'] == "Shulman group"]
    before5 = res.loc[res['case'] == "manrs-low"]

    after1 = res2.loc[res2['case'] == "no added rov"]
    after3 = res2.loc[res2['case'] == "manrs-high"]
    after2 = res2.loc[res2['case'] == "RoVISTA"]
    after4 = res2.loc[res2['case'] == "Shulman group"]
    after5 = res2.loc[res2['case'] == "manrs-low"]

    y1 = [float(before1['matched_before']), float(before3['matched_before']), float(before2['matched_before']), float(before4['matched_before']), float(before5['matched_before'])]
    y2 = [float(after1['matched_after']), float(after3['matched_after']), float(after2['matched_after']), float(after4['matched_after']), float(after5['matched_after'])]


    y1 = [float(before1['matched_before']), float(before3['matched_before']), float(before2['matched_before']), float(before4['matched_before']), float(before5['matched_before'])]
    y2 = [float(after1['matched_after']), float(after3['matched_after']), float(after2['matched_after']), float(after4['matched_after']), float(after5['matched_after'])]


    for i in range(len(y1)):
        print(y2[i]/y1[i])
    
    barWidth = 0.25
    fig = plt.subplots(figsize =(12, 8))
    br1 = np.arange(len(y1))
    br2 = [x + barWidth for x in br1]

    plt.bar(br1, y1, width = barWidth, edgecolor ='grey', label ='before optimization', color=CB_color_cycle[0])
    plt.bar(br2, y2, width = barWidth, edgecolor ='grey', label ='after optimization', color=CB_color_cycle[1])

    plt.xlabel('ROV data source', fontweight ='bold', fontsize = 24)
    plt.ylabel('%  ROA ROV matched pairs', fontweight ='bold', fontsize = 24)
    #plt.title('Percentage of ROA ROV matched client-relay pairs', fontsize=24)
    # plt.xticks([r + barWidth for r in range(len(y1))], ["no added rov", "top 100", " top 20%", "rov match all roa", "random 10%"])
    plt.xticks([r + barWidth for r in range(len(y1))], ["base", "manrs-high", "RoVISTA", "Hlavacek", "manrs-low"])
    plt.xticks(fontsize=22)
    plt.yticks(fontsize=22)
    plt.legend(fontsize=22)
    # plt.show()
    plt.savefig('matching-results.png', bbox_inches='tight', dpi=599)


def get_next_date(start_date):
    # all possible days for all months
    days1 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31']
    days2 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30']
    days3 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28']
    days4 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29']

    # get current date
    y = start_date.split("-")[0]
    m = start_date.split("-")[1]
    d = start_date.split("-")[2]

    # compute next date
    if int(y) % 4  == 0:
        quadrennial = True
    else:
        quadrennial = False

    if quadrennial == True and m == "02":
        days = days4
    elif quadrennial == False and m == "02":
        days = days3
    elif m == "01" or m == "03" or m =="05" or m=="07" or m=="08" or m =="10" or m=="12":
        days = days1
    elif m == "04" or m=="06" or m=="09" or m=="11":
        days = days2

    new_y = y
    new_m = m
    new_d = d

    if d != days[-1]:
        new_d = days[days.index(d) + 1]
        new_date = y + "-" + m + "-" + new_d
        return new_date
    else:
        if m != 12:
            new_m = int(m) + 1
            if new_m < 10:
                new_m = "0" + str(new_m)
            new_date = y + "-" + str(new_m) + "-" + "01"
            return new_date
        else:
            new_y = int(y) + 1
            new_date = str(new_y) + "-" + "01" + "-" + "01"
            return new_date
    

# main function - starts simulation from 2021-01 to 2023-05
def run_sim(start_date_global, end_date_global, initialize):
    start_time = time.time()
    hours = ['00']

    # output lists
    date_strings = []
    case_strings = []
    m1 = []
    m2 = []
    m3 = []
    m4 = []
    m5 = []
    m6 = []

    # current directory as the root directory
    root = os.getcwd()

    file =  open('./ASNwROV.pickle', 'rb') #open a file where a list of ASN with ROV is kept 
    ROVset = list(pickle.load(file))
    file.close()

    # use variable for client generation for the first iteration
    if initialize:
        gen_clients = True
    else:
        gen_clients = False

    wa_roa_save = 0
    wa_rov_save = 0
    wa_both_save = 0
    wa_neither_save = 0
    countreis_save = []
    cweights_save = []

    y = start_date_global.split("-")[0]
    m = start_date_global.split("-")[1]
    d = start_date_global.split("-")[2]
    
    consensus_date_formal = y + "-" + m + "-" + d

    # next_date_global = get_next_date(start_date_global)
    
    while consensus_date_formal != end_date_global:
        y = consensus_date_formal.split("-")[0]
        m = consensus_date_formal.split("-")[1]
        d = consensus_date_formal.split("-")[2]

        consensus_date = y + m + d
        load_time_start = time.time()

        # find routeview data for that month
        os.chdir(root)
        os.chdir("../routeviews")
        rvlist = glob.glob("*.pfx2as")
        for rv in rvlist:
            if consensus_date in rv and "-rv2-" in rv:
                rv2 = rv
            if consensus_date in rv and "-rv6-" in rv:
                rv6 = rv

        # make ASN -> AS object
        ASNnumIP1 = getAllAS3(rv2)
        # ASNnumIP2 = getAllAS3(rv6)
        ASNnumIP = ASNnumIP1.copy()
        # ASNnumIP.update(ASNnumIP2)
        
        # maps ASN -> orgID, maps orgID -> origin
        asn_orgID, orgID_origin = preprocess_asn_origin('../20240401.as-org2info.txt')

        # update ASNnumIP to include origin, ASN -> AS object
        numIPdict = get_origin(asn_orgID, orgID_origin, ASNnumIP)

        # get ASN -> IP prefix dictionary
        # v4MAPDICT, v4QUICKDICT = process_routeview_v4(rv2)
        # v6MAPDICT, v6QUICKDICT = process_routeview_v6(rv6)
        os.chdir(root)
        print("Done processing ROUTEVIEW file")
        asndb = pyasn.pyasn('ipasn_2024-07-12.dat')

        for h in hours:
            consensus_date_with_hour = y + "-" + m + "-" + d + "-" + h
            
            next_date_global = get_next_date(consensus_date_formal)

            # process consensus data
            start_date = consensus_date_with_hour.split('-')
            end_date = (next_date_global + "-" + h).split("-")
            for i in range(4):
                start_date[i] = int(start_date[i])
                end_date[i] = int(end_date[i])
            start_date = datetime(start_date[0], start_date[1], start_date[2], start_date[3])
            end_date = datetime(end_date[0], end_date[1], end_date[2], end_date[3])            
            
            all_ipv4s, all_ipv6s = pickle_consensus(start_date, end_date)
            print("Done processing CONSENSUS file")

            # get prefix and asn for each relay
            # get dictionary mapping ip to prefix, asn
            # return dicts: key: ip -> value: [prefix, asn]
            ipv4_asns, ipv6_asns = get_pre_asn(all_ipv4s, all_ipv6s, asndb)
            print("Done mapping all ipv4 and ipv6 to ASN and prefix")

            # create coverage dict 
            # dicts: key: ip -> value: [ip, maxlen, prefixlen, asn] (ROA)
            os.chdir(root)
            os.chdir("../mergedROAs")
            roalist = glob.glob("*.csv")
            for r in roalist:
                if consensus_date in r:
                    roa_file = r
            v4, v6 = coverage_dict(roa_file, all_ipv4s, all_ipv6s)
            print("Done parsing ROA input")

            # create consensus pickle with ROA coverage dict and prefix, asn information
            update_consensus_pickle(start_date, end_date, v4, v6, ipv4_asns, ipv6_asns)
        
            with open("/home/ubuntu/TOR-RPKI/v4.pickle", 'wb') as f_pc1:
                pickle.dump(v4, f_pc1)
            print("Done updating pickles")
            os.chdir(root)

            end_load_time = time.time()

            print("what is load time = ", end_load_time - load_time_start) 
            matched2, wa_both, wa_roa, wa_rov, wa_neither, countries, cweights = user_specified_client2(consensus_date_with_hour, 1000000, roa_file, numIPdict, ROVset, wa_both_save, wa_roa_save, wa_rov_save, wa_neither_save, countreis_save, cweights_save, gen_clients, 2)
            
            #date_strings.append(consensus_date_with_hour)
            #case_strings.append("RoVISTA")
            #m2.append(matched2)
            #m3.append(wa_both)
            #m4.append(wa_roa)
            #m5.append(wa_rov)
            #m6.append(wa_neither)

            #gen_clients = False   
            #wa_roa_save = wa_roa
            #wa_rov_save = wa_rov
            #wa_both_save = wa_both
            #wa_neither_save = wa_neither
            #countreis_save = copy.deepcopy(countries)
            #cweights_save = copy.deepcopy(cweights)
        
            #print("finished " + str(consensus_date_with_hour))   

            #da = {'date': date_strings, 'case': case_strings, "matched_after": m2, "both_clients": m3, "roa_clients": m4, "rov_clients": m5, "neither_clients": m6}
            #df = pd.DataFrame(data = da)
            #df.to_csv("./output-matching" + str(consensus_date_with_hour) + ".csv", index=False)
        
        consensus_date_formal = get_next_date(consensus_date_formal)
    end_time = time.time()
    print("what does it take to complete one iter = ", end_time - start_time)


start_date = "2024-05-01"
end_date = "2024-05-02"
initialize = False
run_sim(start_date, end_date, initialize)
