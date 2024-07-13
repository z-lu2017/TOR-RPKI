from util import *
import sys
import argparse
import shutil
import time
import upgradeIpASNMap
import os

# v4MAPDICT, v4QUICKDICT = upgradeIpASNMap.preprocess_get_prefix_asn_local_v4()
# v6MAPDICT, v6QUICKDICT = upgradeIpASNMap.preprocess_get_prefix_asn_local_v6()

v4MAPDICT, v4QUICKDICT = None, None
v6MAPDICT, v6QUICKDICT = None, None
# place archived consensuses in folder called archive
def archive_consensus(year, month, date, hour):
    ''' Pulls relay info from consensus file
    helper for pickle_consensus, read in raw consensus file from archive folder 
    and return a list of relay object with basic info assigned

    
    :param year: (str) year of the consensus file
    :param month: (str) month of consensus file
    :param date: (str) date of consensus file
    :param hour: (str) hr of consensus file 
    :return: (list) list of Relay objects, (int) wgd, (int), wgg
    '''

    # Set up path
    cwd = os.getcwd()
    monthDirectory = r'/consensuses-' + year + '-' + month
    dateDirectory = '//' + date
    filename = '//' + year + '-' + month + '-' + date + '-' + hour + '-00-00-consensus'
    path = cwd + r'/archive' + monthDirectory + dateDirectory + filename
    # If file exists, open it
    try:
        with open(path, 'r') as f:
            lines = f.read().split('\n') #read all input, split with newline character
            rs = []
            wgg = False
            wgd = False
            # iterate through each line to get info on relay 
            for line in lines:
                # Bandwidth weights for this consensus
                # print("what is line = ", line)
                if line.strip() != "":
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


def get_all_ips(start_date, end_date):

    """go through all archive_pickles files in 
    a time span get the ip address of all relays 

    :param start_date: (datetime object) start of the duration
    :param end_date: (datetime object) end of the duration
    :return: the set of all ipv4 and ipv6 addresses 
    """
    all_ipv4s = set()
    all_ipv6s = set()
    p = os.getcwd()
    path = p + '//archive_pickles//'
    for t in datespan(start_date, end_date, delta=timedelta(hours=1)):
        rs, wgd, wgg = load_consensus(path, t.strftime('%Y'), t.strftime('%m'), t.strftime('%d'), t.strftime('%H'))
        if rs:
            ipv4s = [r.ip for r in rs]
            ipv6s = [r.ipv6 for r in rs if r.ipv6 != '']
            all_ipv4s.update(ipv4s)
            all_ipv6s.update(ipv6s)
    return all_ipv4s, all_ipv6s

# need directory called archive_pickles for intermediate pickles w/o ROA info + asn/prefix info
def pickle_consensus(start_date, end_date, gen_all_ip_pickles=False):
    '''call archive_consensus to get a list of relay objects, pickle and move them into archive_pickles folder
    :param start_date: (datetime object) start of the duration
    :param end_date: (datetime object) end of the duration
    :param gen_all_ip_pickles: (boolean) produce pickle with all ip addresses if true

    :return: set of IPv4 and IPv6 addresses if gen_all_ip_pickles true, else return None 
    '''
    path = os.getcwd()
    # path = os.path.split(path)[0] + '//archive//'
    path = path + '//archive_pickles//'
    all_ipv4s = set()
    all_ipv6s = set()
    for t in datespan(start_date, end_date, delta=timedelta(hours=1)):
        #get relay objects in time duration
        rs, wgd, wgg = archive_consensus(t.strftime('%Y'), t.strftime('%m'), t.strftime('%d'), t.strftime('%H'))
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
    #option to generate pickle with all ip addresses in them
    if gen_all_ip_pickles:
        filename2 = 'all-ips.pickle'
        with open(filename2, 'wb') as f_pc2:
            pickle.dump(all_ipv4s, f_pc2)
            pickle.dump(all_ipv6s, f_pc2)
    return all_ipv4s, all_ipv6s

# could be done faster if you just used BGP dumps to find what prefix / asn each relay is announced with
def get_pre_asn(ipv4s, ipv6s, make_pickle=False, existing_file=False):
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
        with open('relay_asns.pickle', 'rb') as ef:
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
        # print(ip)
        if countv6 % 100 == 0:
            print("v6 running at: ", countv6)
        pre, asn = get_prefix_and_asn_local(ip)
        if len(asn) != 1:
            print(ip + ' is in ' + str(len(asn)) + ' ASes')
        if len(asn) == 0:
            ipv6s_asns.setdefault(ip, [pre, None])
        else:
            ipv6s_asns.setdefault(ip, [pre, asn])
        countv6 += 1

    countv4 = 0
    for ip in ipv4s:
        if countv4 % 100 == 0:
            print(" v4 running at: ", countv4)

        pre, asn = get_prefix_and_asn_local(ip)
        if len(asn) != 1:
            print(ip + ' is in ' + str(len(asn)) + ' ASes')
        if len(asn) == 0:
            ipv4s_asns.setdefault(ip, [pre, None])
        else:
            ipv4s_asns.setdefault(ip, [pre, asn])
        countv4 +=1
    if make_pickle:
        with open('relay_asns.pickle', 'wb') as f_pa:
            pickle.dump(ipv4s_asns, f_pa)
            pickle.dump(ipv6s_asns, f_pa)
    return ipv4s_asns, ipv6s_asns


def get_roas(filename):
    '''parse roa file in .csv format, put each entry in a list, then append to a list containing all entries.
    each line in the file converts into [ipv4, maxlen, prefixlen, asn]

    :param filename: (string) name of the csv file to parse 
    :return: 2 lists of list for ipv4 and ipv6 addresses, entry in each list is [ipv4, maxlen, prefixlen, asn]
    ''' 
    # read csv file
    ipv4s = []
    ipv6s = []
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
                ipv6 = ipaddress.IPv6Network(row[1])
                maxlen = row[2]
                prefixlen = row[1].split('/')[1]
                if 'AS' not in row[0]:
                    asn = row[0]
                else:
                    asn = row[0][2:]
                ipv6s.append([ipv6, maxlen, prefixlen, asn])

    return ipv4s, ipv6s


def coverage_dict(roas, ipv4s, ipv6s, make_pickle=False):
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
    if make_pickle:
        with open('coverage.pickle', 'wb') as f_cd1:
            pickle.dump(v4coverage, f_cd1)
            pickle.dump(v6coverage, f_cd1)
    #maps ip address to roa list 
    return v4coverage, v6coverage


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

# need directory called processed
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
    archivePath = p + '/archive_pickles/'
    resultPath = p + '/processed/'
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

def get_prefix_and_asn_local(ip):
    """
    wrapper function to get prefix and ASN given an ip address

    :param ip: (str) ip address in string 

    :return: ip prefix in ipaddress module object, ASN 

    """
    global v6QUICKDICT
    global v6MAPDICT
    global v4QUICKDICT
    global v4MAPDICT
    if ':' in ip:
        return upgradeIpASNMap.get_prefix_and_asn_local_v6(v6QUICKDICT, v6MAPDICT,ip)
    if '.' in ip:
        return upgradeIpASNMap.get_prefix_and_asn_local_v4(v4QUICKDICT, v4MAPDICT, ip)


def parse_arguments(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("start_date", help="date in year-mo-da-hr format")
    parser.add_argument("end_date", help="date in year-mo-da-hr format (not inclusive)")
    parser.add_argument("roas", help="csv file of validated ROAs")
    parser.add_argument("routeviews", help="routeview mapping file")
    parser.add_argument("routeviewsv6", help="routeview mapping file for ipv6")
    return parser.parse_args(args)


def main(args):
    """
    sample usage: python3 preprocess_consensus.py 2021-01-01-00 2021-01-02-01 ./mergedROAs/20210101.csv ./routeviews/routeviews-rv2-20210101-1200.pfx2as ./routeviews/routeviews-rv6-20210101-1200.pfx2as
    Put raw consensus file into archive folder, this main function will make relay objects and pickle them in archive_pickles folder
    The relay objects with ROA coverage and ip, asn information will be placed in the processed folder 
    """
    global v6QUICKDICT
    global v6MAPDICT
    global v4QUICKDICT
    global v4MAPDICT
    args = parse_arguments(args)
    v4MAPDICT, v4QUICKDICT = upgradeIpASNMap.preprocess_get_prefix_asn_local_v4(args.routeviews)
    v6MAPDICT, v6QUICKDICT = upgradeIpASNMap.preprocess_get_prefix_asn_local_v6(args.routeviewsv6)
    #retrieve and format argument 
    start_time = time.time()
    
    start_date = args.start_date.split('-')
    end_date = args.end_date.split('-')
    for i in range(4):
        start_date[i] = int(start_date[i])
        end_date[i] = int(end_date[i])
    start_date = datetime(start_date[0], start_date[1], start_date[2], start_date[3])
    end_date = datetime(end_date[0], end_date[1], end_date[2], end_date[3])

    # pickle consensus
    #get a list of relay objects
    all_ipv4s, all_ipv6s = pickle_consensus(start_date, end_date)   # set of all ip addresses
    print("--- %s seconds to preprocess consensuses ---" % (time.time() - start_time))
    start_time = time.time()

    # get prefix and asn for each relay
    #get dictionary mapping ip to prefix, asn
    # return dicts: key: ip -> value: [prefix, asn]
    # get_pre_asn(ipv4s, ipv6s, make_pickle=False, existing_file=False):
    ipv4_asns, ipv6_asns = get_pre_asn(all_ipv4s, all_ipv6s, False, True) 
    print("--- %s seconds to get prefix and ASN ---" % (time.time() - start_time))
    start_time = time.time()

    # create coverage dict 
    # dicts: key: ip -> value: [ip, maxlen, prefixlen, asn] (ROA)
    v4, v6 = coverage_dict(args.roas, all_ipv4s, all_ipv6s, True)         
    print("--- %s seconds to create coverage dict ---" % (time.time() - start_time))
    start_time = time.time()

    # create consensus pickle with ROA coverage dict and prefix, asn information
    update_consensus_pickle(start_date, end_date, v4, v6, ipv4_asns, ipv6_asns)
    print("--- %s seconds to update consensus pickles ---" % (time.time() - start_time))

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
