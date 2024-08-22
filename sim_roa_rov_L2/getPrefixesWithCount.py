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
def get_pre_asn(ipv4s, ipv6s, asndb, make_pickle=False, existing_file=False):
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

# helper function to grab client geographic distribution
def grab_client_geo_dist(consensus_date):
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
          

    # if len(countries) == 0 or len(cweights) == 0:
    #     print("Tor metrics error! user previous iteration data")
    #     if len(countries_last) > 0:
    #         countries = countries_last
    #         cweights = cweights_last
    #     else:
    #         # hard-coded average as backup
    #         return ["Germany", "United States", "Netherlands", "Ukraine", "Finland", "India", "Lithuania", "Indonesia", "France", "Spain"], [0.5349, 0.1077,0.0360, 0.0313,0.0298,0.0177,0.0164,0.0129,0.0125,0.0118]

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

    # output lists
    default_value = []
    both_prefixes_out = dict.fromkeys(countries, default_value)
    roa_prefixes_out = dict.fromkeys(countries, default_value)
    rov_prefixes_out = dict.fromkeys(countries, default_value)
    neither_prefixes_out = dict.fromkeys(countries, default_value)

    default_value2 = 0
    both_prefixes_count = dict.fromkeys(countries, default_value2)
    roa_prefixes_count = dict.fromkeys(countries, default_value2)
    rov_prefixes_count = dict.fromkeys(countries, default_value2)
    neither_prefixes_count = dict.fromkeys(countries, default_value2)

    both_prefixes_out['other'] = []
    roa_prefixes_out['other'] = []
    rov_prefixes_out['other'] = []
    neither_prefixes_out['other'] = []

    both_prefixes_count['other'] = 0
    roa_prefixes_count['other'] = 0
    rov_prefixes_count['other'] = 0
    neither_prefixes_count['other'] = 0

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

                prefix_separated = prefixes[i].split('/')[1]
                
                if roa == True and rov == True:
                    both_prefixes_out[c].append(prefixes[i])
                    both_prefixes_count[c] += int(prefixHosts[int(prefix_separated)])
                if roa == True and rov == False:
                    roa_prefixes_out[c].append(prefixes[i])
                    roa_prefixes_count[c] += int(prefixHosts[int(prefix_separated)])
                if roa == False and rov == True:
                    rov_prefixes_out[c].append(prefixes[i])
                    rov_prefixes_count[c] += int(prefixHosts[int(prefix_separated)])
                if roa == False and rov == False:
                    neither_prefixes_out[c].append(prefixes[i])
                    neither_prefixes_count[c] += int(prefixHosts[int(prefix_separated)])
                
    
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

            if roa == True and rov == True:
                both_prefixes_out['other'].append(prefixes[i])
                both_prefixes_count['other'] += int(prefixHosts[int(prefix_separated)])
            if roa == True and rov == False:
                roa_prefixes_out['other'].append(prefixes[i])
                roa_prefixes_count['other'] += int(prefixHosts[int(prefix_separated)])
            if roa == False and rov == True:
                rov_prefixes_out['other'].append(prefixes[i])
                rov_prefixes_count['other'] += int(prefixHosts[int(prefix_separated)])
            if roa == False and rov == False:
                neither_prefixes_out['other'].append(prefixes[i])
                neither_prefixes_count['other'] += int(prefixHosts[int(prefix_separated)])
   
   

    return both_prefixes_out, roa_prefixes_out, rov_prefixes_out, neither_prefixes_out, both_prefixes_count, roa_prefixes_count, rov_prefixes_count, neither_prefixes_count


# main function for generating users and choosing guards
def user_specified_client2(consensus_date, numClients, csvfile, numIPdict, rovset, method = 0):
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

    countries, cweights = grab_client_geo_dist(consensus_date)

    both_prefixes_out, roa_prefixes_out, rov_prefixes_out, neither_prefixes_out, both_prefixes_count, roa_prefixes_count, rov_prefixes_count, neither_prefixes_count = calc_roa_rov_client(countries, cweights, numIPdict, csvfile, rovset)
        
    return both_prefixes_out, roa_prefixes_out, rov_prefixes_out, neither_prefixes_out, both_prefixes_count, roa_prefixes_count, rov_prefixes_count, neither_prefixes_count


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
    

def run_sim(start_date_global):
    hours = ['00']

    # current directory as the root directory
    root = os.getcwd()

    file =  open('./ASNwROV.pickle', 'rb') #open a file where a list of ASN with ROV is kept 
    ROVset = list(pickle.load(file))
    file.close()

    y = start_date_global.split("-")[0]
    m = start_date_global.split("-")[1]
    d = start_date_global.split("-")[2]
    
    consensus_date_formal = y + "-" + m + "-" + d

    y = consensus_date_formal.split("-")[0]
    m = consensus_date_formal.split("-")[1]
    d = consensus_date_formal.split("-")[2]

    consensus_date = y + m + d

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

        print("Done updating pickles")
        os.chdir(root)

        both_prefixes, roa_prefixes, rov_prefixes, neither_prefixes, both_prefixes_count, roa_prefixes_count, rov_prefixes_count, neither_prefixes_count = user_specified_client2(consensus_date_with_hour, 1000000, roa_file, numIPdict, ROVset, 2)
        
        with open('both-prefixes.pickle', 'wb') as f_cd1:
            pickle.dump(both_prefixes, f_cd1)

        with open('roa-prefixes.pickle', 'wb') as f_cd1:
            pickle.dump(roa_prefixes, f_cd1)

        with open('rov-prefixes.pickle', 'wb') as f_cd1:
            pickle.dump(rov_prefixes, f_cd1)

        with open('neither-prefixes.pickle', 'wb') as f_cd1:
            pickle.dump(neither_prefixes, f_cd1)

        with open('both-prefixes-count.pickle', 'wb') as f_cd1:
            pickle.dump(both_prefixes_count, f_cd1)

        with open('roa-prefixes-count.pickle', 'wb') as f_cd1:
            pickle.dump(roa_prefixes_count, f_cd1)

        with open('rov-prefixes-count.pickle', 'wb') as f_cd1:
            pickle.dump(rov_prefixes_count, f_cd1)

        with open('neither-prefixes-count.pickle', 'wb') as f_cd1:
            pickle.dump(neither_prefixes_count, f_cd1)
        


start_date = "2024-05-01"
run_sim(start_date)