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
import re

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

def check_rovset(asn, rovset):
    found = False
    for i in range(len(rovset)):
        if int(asn) == int(rovset[i].strip()):
            found = True
            return found
    return found

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
    ipv4_count = 0
    ipv6_count = 0
    both_count = 0
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
                    r = Relay(r_info[1], r_info[2], r_info[5])
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

            for r in rs:
                if r.ip and r.ipv6 != '':
                    both_count += 1
                elif r.ip and r.ipv6 == '':
                    ipv4_count += 1
                else:
                    ipv6_count += 1


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
    total = 0
    count = 0
    # iterate through consensus pickles
    for t in datespan(start_date, end_date, delta=timedelta(hours=1)):
        # load old pickle
        rs, wgd, wgg = load_consensus(archivePath, t.strftime('%Y'), t.strftime('%m'), t.strftime('%d'), t.strftime('%H'))
        if rs:
            updated_rs = []
            for r in rs:
                total += 1
                r.ipv4_prefix = ipv4_asns[r.ip][0]
                r.asn = ipv4_asns[r.ip][1]
                r.ipv4_roa = v4coverage[r.ip]
                if r.ipv6 != '':
                    # print("what is r.ipv6 = ", r.ipv6)
                    # print("what is asn dic = ", ipv6_asns[r.ipv6])
                    r.ipv6_prefix = ipv6_asns[r.ipv6][0]
                    r.ipv6_asn = ipv6_asns[r.ipv6][1]
                    r.ipv6_roa = v6coverage[r.ipv6]
                    #if r.ipv6_asn != r.asn:
                    #    print(r.ip + ' in ' + str(r.asn) + '. ' + r.ipv6 + ' in ' + str(r.ipv6_asn))
                if r.ipv4_roa != None or r.ipv6_roa != None:
                    count += 1
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
    print("========================================================")
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

# main function for generating users and choosing guards
def user_specified_client2(consensus_date, numClients, csvfile, numIPdict, rovset = None, saveClients = False, discount = 0.7):
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
    global cweights
    global countries

    # lists used for optimization - weights1 vanilla weight weights2 discounted weight
    weights1 = []
    weights2 = []
    croas = []
    crovs = []
    bws = []

    # parameters used for discounting
    # discount = 0.7 # no roa penalty

    # handle no filter case
    if rovset == None:
        rovset = []

    #pull in country data as global variable 
    resultClientList = []

    # read in prefix to IP address map
    prefixHosts = get_prefix_addresses_map() # prefix -> number of ip address

    # read in consensus and parse guards with bandwidth
    p = '../processed/' + consensus_date + '-processed.pickle'

    #try to open the pickled file  
    try:
        file = open(p, 'rb')
    except FileNotFoundError:
        print(p, 'does not exist')
   
    # process consensus and collect guard relays info
    rs = pickle.load(file) #list of all relay objects
    WGD = pickle.load(file) #weight in the consensus
    WGG = pickle.load(file) #weight in the consensus
    gs = [r for r in rs if r.is_guard] #get all the guards relay in a list

    guardsROA = 0

    
    # build guard weights relay and roa/rov coverage
    for r in gs: #iterate through all relays within the guards relays list
        if r.is_exit:  # if r is an exit
            if r.ipv4_roa != None: #the relay has roa 
                w = int(r.bw * WGD)  # wgd, g+e in g position
                weights1.append(w)
                bws.append(r.bw)
                weights2.append(w)
                guardsROA += 1

            else:
                w = int(r.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
                weights1.append(w)
                bws.append(r.bw)
                w = w * discount
                weights2.append(w)
        else:
            if r.ipv4_roa != None: #the relay has roa 
                w = int(r.bw * WGG)  # wgg, g in g position
                weights1.append(w)
                bws.append(r.bw)
                weights2.append(w)
                guardsROA += 1
            else:
                w = int(r.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
                weights1.append(w)
                bws.append(r.bw)
                w = w * discount
                weights2.append(w)

    consensus_date = consensus_date.split('-')
    
    t  = datetime(int(consensus_date[0]),int(consensus_date[1]),int(consensus_date[2]),int(consensus_date[3]))

    before = []
    after = []
    
    for j in range(1):
        # count pre matching results
        roa_cov = 0
        average_bw = sum(bws) / len(bws)

        dynamic_guards = {}
        for g in gs:
            dynamic_guards[g] = 0
    
        for k in range(numClients):
            # get client coverage info
            i = random.choices(range(len(weights1)), weights = weights1, k=1)[0]
            chosenGuard = gs[i]
            dynamic_guards[chosenGuard] += 1

            if chosenGuard.is_exit:  # if r is an exit
                if chosenGuard.ipv4_roa != None: #the relay has roa 
                    w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
                else:
                    w = int(chosenGuard.bw * WGD * discount) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
            else:
                if chosenGuard.ipv4_roa != None: #the relay has roa 
                    w = int(chosenGuard.bw * WGG)  # wgg, g in g position
                else:
                    w = int(chosenGuard.bw * WGG * discount) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

            if w/dynamic_guards[chosenGuard] <= average_bw:
                # print("hitting threshold, remove relay" + str(i) + " from selection")
                weights1[i] = 0
            # compute matched
            try:
                if chosenGuard.ipv4_roa != None:
                    roa_cov += 1
            except:
                pass
            
        # print("Done guard selection vanilla")
        # print("===========================================================")

        roa_cov2 = 0
        dynamic_guards = {}
        for g in gs:
            dynamic_guards[g] = 0

        for k in range(numClients):
            # get client coverage info
            i = random.choices(range(len(weights2)), weights = weights2, k=1)[0]
            chosenGuard = gs[i]
            dynamic_guards[chosenGuard] += 1

            if chosenGuard.is_exit:  # if r is an exit
                if chosenGuard.ipv4_roa != None: #the relay has roa 
                    w = int(chosenGuard.bw * WGD)  # wgd, g+e in g position
                else:
                    w = int(chosenGuard.bw * WGD * discount) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
            else:
                if chosenGuard.ipv4_roa != None: #the relay has roa 
                    w = int(chosenGuard.bw * WGG)  # wgg, g in g position
                else:
                    w = int(chosenGuard.bw * WGG * discount) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below

            if w/dynamic_guards[chosenGuard] <= average_bw:
                # print("hitting threshold, remove relay" + str(i) + " from selection")
                weights2[i] = 0
                # chosenGuard = random.choices(gs, weights = optimized_weights, k=1)[0]
            # compute matched
            try:
                if chosenGuard.ipv4_roa != None:
                    roa_cov2 += 1
            except:
                pass
        
        roa_cov = float(roa_cov/numClients)
        roa_cov2 = float(roa_cov2/numClients)
        before.append(roa_cov)
        after.append(roa_cov2)

        # print("Done guard selection with discount")
        # print("===========================================================")
        
    return before, after

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

# main function - starts simulation from 2021-01 to 2024-05
def run_sim():
    # date range to iterate through
    years = ['2021', '2022', '2023','2024']
    months = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12']
    months2 = ['01', '02', '03', '04', '05']
    hours = ['00']

    # output lists
    date_strings = []
    discounts = []
    roa_coverage1 = []
    roa_coverage2 = []

    # current directory as the root directory
    root = os.getcwd()

    saveClients = True
    years = ['2024']
    for y in years:
        if y == "2024":
            months_final = months2
        else:
            months_final = months
        months_final = ['05']
        for m in months_final:
            consensus_date = y + m + "01"

            # find routeview data for that month
            os.chdir(root)
            os.chdir("../routeviews")
            rvlist = glob.glob("*.pfx2as")
            for rv in rvlist:
                if consensus_date in rv and "-rv2-" in rv:
                    rv2 = rv

            # make ASN -> AS object
            ASNnumIP1 = getAllAS3(rv2)
            ASNnumIP = ASNnumIP1.copy()
            
            # maps ASN -> orgID, maps orgID -> origin
            asn_orgID, orgID_origin = preprocess_asn_origin('../20240401.as-org2info.txt')

            # update ASNnumIP to include origin, ASN -> AS object
            numIPdict = get_origin(asn_orgID, orgID_origin, ASNnumIP)

            # get ASN -> IP prefix dictionary
            # v4MAPDICT, v4QUICKDICT = process_routeview_v4(rv2)
            # v6MAPDICT, v6QUICKDICT = process_routeview_v6(rv6)
            os.chdir(root)
            print("Done processing ROUTEVIEW file")
            asndb = pyasn.pyasn('../ipasn_2024-07-12.dat')

            for h in hours:
                consensus_date_with_hour = y + "-" + m + "-01-" + h
                # process consensus data
                start_date = consensus_date_with_hour.split('-')
                end_date = list(start_date)
                end_date[2] = int(end_date[2]) + 1
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

                # # # create clients and simulate client guard node selection
                discount_list = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

                for d in discount_list:
                    roa_cov, roa_cov2 = user_specified_client2(consensus_date_with_hour, 1000000, roa_file, numIPdict, None, saveClients, d)
                    saveClients = False
                    for i in range(len(roa_cov)):
                        date_strings.append(consensus_date_with_hour)
                        discounts.append(d)
                        roa_coverage1.append(roa_cov[i])
                        roa_coverage2.append(roa_cov2[i])

                print("finished year = " + y + " month = " + m)
    

    d = {'date': date_strings, "discount": discounts, 'roa_coverage_before': roa_coverage1, 'roa_coverage_after': roa_coverage2}
    df = pd.DataFrame(data = d)
    df.to_csv("/home/ubuntu/output-discount.csv", index=False)

# function to simulate load factor
def sim_load():
    # date range to iterate through
    years = ['2021', '2022', '2023', '2024']
    months = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12']
    months2 = ['01', '02', '03', '04', '05']
    hours = ['00']

    # output lists
    date_strings = []
    discounts = []
    loads = []
    utilizations = []

    optimal_date = []
    optimal_discount = []
    optimal_load = []
    optimal_utilization = []

    years = ['2024']

    for y in years:
        if y == "2024":
            months_final = months2
        else:
            months_final = months
        months_final = ['05']
        for m in months_final:
            for h in hours:
                consensus_date_with_hour = y + "-" + m + "-01-" + h
                possible_discounts = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1]
                possible_loads = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1]

                # read in consensus and parse guards with bandwidth
                p = '../processed/' + consensus_date_with_hour + '-processed.pickle'

                #try to open the pickled file  
                try:
                    file = open(p, 'rb')
                except FileNotFoundError:
                    print(p, 'does not exist')
                # process consensus and collect guard relays info
                rs = pickle.load(file) #list of all relay objects
                WGD = pickle.load(file) #weight in the consensus
                WGG = pickle.load(file) #weight in the consensus
                gs = [r for r in rs if r.is_guard] #get all the guards relay in a list


                for l in possible_loads:
                    foundOptimal = False
                    for d in possible_discounts:
                        weights1 = []
                        weights2 = []
                        bws = []
                        # build guard weights relay and roa/rov coverage
                        for r in gs: #iterate through all relays within the guards relays list
                            if r.is_exit:  # if r is an exit
                                if r.ipv4_roa != None: #the relay has roa 
                                    w = int(r.bw * WGD)  # wgd, g+e in g position
                                    weights1.append(w)
                                    bws.append(r.bw)
                                    weights2.append(w)

                                else:
                                    w = int(r.bw * WGD) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
                                    weights1.append(w)
                                    bws.append(r.bw)
                                    w = w * d
                                    weights2.append(w)
                            else:
                                if r.ipv4_roa != None: #the relay has roa 
                                    w = int(r.bw * WGG)  # wgg, g in g position
                                    weights1.append(w)
                                    bws.append(r.bw)
                                    weights2.append(w)
                                else:
                                    w = int(r.bw * WGG) #does not have roa, so multiply discount and add to the total weight var, modify after optimization below
                                    weights1.append(w)
                                    bws.append(r.bw)
                                    w = w * d
                                    weights2.append(w)

                        # calculate expected actual load
                        total_actual_traffic = 0
                        for i in range(len(weights2)):
                            p = weights2[i] / sum(weights2)
                            traffic = p * l *sum(weights1)
                            if traffic > weights2[i]:
                                traffic = weights2[i]
                            total_actual_traffic += traffic

                        utilization = total_actual_traffic / sum(weights1)
                        date_strings.append(consensus_date_with_hour)
                        loads.append(l)
                        discounts.append(d)
                        utilizations.append(utilization)
                        if not foundOptimal and abs(utilization - l) <= 0.0001:
                            foundOptimal = True
                            optimal_date.append(consensus_date_with_hour)
                            optimal_load.append(l)
                            optimal_discount.append(d)
                            optimal_utilization.append(utilization)
                        elif foundOptimal and abs(utilization - optimal_utilization[-1]) <= 0.001 and d < optimal_discount[-1]:
                            optimal_date.pop()
                            optimal_load.pop()
                            optimal_discount.pop()
                            optimal_utilization.pop()
                            optimal_date.append(consensus_date_with_hour)
                            optimal_load.append(l)
                            optimal_discount.append(d)
                            optimal_utilization.append(utilization)

    

    d = {'date': date_strings, "discount": discounts, 'load': loads, 'utilizations': utilizations}
    df = pd.DataFrame(data = d)
    df.to_csv("/home/ubuntu/output-discount-load.csv", index=False)

    d = {'date': optimal_date, "discount": optimal_discount, 'load': optimal_load}
    df = pd.DataFrame(data = d)
    df.to_csv("/home/ubuntu/output-discount-load-optimal.csv", index=False)


run_sim()
sim_load()
