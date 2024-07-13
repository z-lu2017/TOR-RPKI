from util import * 

import argparse
import sys
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import numpy as np
import time

import pickle

def guards(relays):
    """
    input a list of relays and filter out non-guard relays, return a list of guards

    :param relays: (list) list of relay objects

    :return: (list) list of relay objects that all has the guard flag
    """
    guards = []
    for relay in relays:
        if relay.is_guard:
            guards.append(relay)
    return guards
def parse_arguments(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", help="list of concensus to graph roa coverage")
    parser.add_argument("guards", help="graph just guards (y/n)")
    parser.add_argument("v4_or_v6", help="whether plot v4 (y) or v6 (n)")
    return parser.parse_args(args)

def main(args):
    args = parse_arguments(args)
    months = args.filenames.split(",")
    guardsOnly = False
    if args.guards == 'y':
        guardsOnly = True
    if args.v4_or_v6 == 'y':
        graph_roa_multi_months_v4(months, guardsOnly)
    else:  
        graph_roa_multi_months_v6(months, guardsOnly)
    
def graph_roa_multi_months_v4(months, guardsOnly):
    """
    sample call:
    python3 graph_multi_months_roa.py "2021-01-01-00, 2021-02-01-00, 2021-03-01-00, 2021-04-01-00,2021-05-01-00,2021-06-01-00,2021-07-01-00,2021-08-01-00,2021-09-01-00,2021-10-01-00,2021-11-01-00,2021-12-01-00,2022-01-01-00,2022-02-01-00,2022-03-01-00,2022-04-01-00,2022-05-01-00,2022-06-01-00,2022-07-01-00,2022-08-01-00,2022-09-01-00,2022-10-01-00,2022-11-01-00,2022-12-01-00,2023-01-01-00,2023-02-01-00,2023-03-01-00,2023-04-01-00,2023-05-01-00, 2023-06-01-00, 2023-07-01-00, 2023-08-01-00, 2023-09-01-00, 2023-10-01-00, 2023-11-01-00, 2023-12-01-00, 2024-01-01-00, 2024-02-01-00, 2024-03-01-00, 2024-04-01-00, 2024-05-01-00" n y
    """
    v4Protected = []
    v4BWProtected = []
    v4ProtectedTight = []
    validROA = []

    for month in months:
        path = "../processed/" + month.strip() + "-processed.pickle"
        with open(path, 'rb') as f2:
            relays = pickle.load(f2)
        if guardsOnly:
            relays = guards(relays)
        bad_as_set = 0
        nw_bandwidth = 0
        v4_bw_invalid = 0
        v4_invalid = 0
        bad_pl = 0
        invalids = dict()
        bad_asn_and_pl = 0
        bad_asn = 0   
        v4_covered = 0
        v4_bw_covered = 0
        v4_mlpl = 0
        v4_mlpl_valid = 0
        num_relays = len(relays) 
        for relay in relays:
            # bandwidth, num guards
            # total up all bandwidth
            nw_bandwidth += relay.bw
            # ipv4 calculations
            # do the following if this relay has ipv4 roa
            if relay.ipv4_roa is not None and relay.ipv4_prefix is not None and len(relay.ipv4_prefix) != 0 :  # roa = [net(IPv4Network), max length(str), prefix length(str), asn]

                pre_len = relay.ipv4_prefix.split('/')[1]
                # e.g. 142.4.192.0/19 the above code will get the number after "/"
                # max length 
                ml = relay.ipv4_roa[1]    # max length of ROA network
                pl = relay.ipv4_roa[2]    # prefix length of ROA network
                # if max length is not set use prefix length
                if ml == '':
                    ml = pl
                # check if invalid
                if isinstance(relay.asn, int):
                    relay.asn = [str(relay.asn)]

                # check if there is an roa and its validity
                if len(relay.asn) > 1:
                    # relay.asn return a list supposedly with 1 entry which is the asn
                    # make sure the format is valid, inherented this format from get_prefix_and_asn() in util.py
                    print("invalid multi asn")
                    bad_as_set += 1
                    v4_invalid += 1
                    v4_bw_invalid += relay.bw

                elif relay.asn[0] != relay.ipv4_roa[3] and int(float(pre_len)) > int(float(ml)):
                    # compare asn obtained from requesting website and the roa file
                    # relay.asn[0] obtain from web, relay.ipv4_roa[3] obtained from ROA file
                    # relay.ipv4_roa =  [IPv4Network('142.4.192.0/19'), '19', '19', '16276']
                    #                   [net(IPv4Network), max length(str), prefix length(str), asn]
                    # check if prefix is longer than max length
                    # defining a max length would be vulnerable to a more specific BGP hijack?

                    print("invalid both asn mismatch and prefix not match")
                    if relay.asn[0] in invalids:
                        invalids[relay.asn[0]][0] += 1
                    else:
                        invalids.setdefault(relay.asn[0], [1, 0, 0])
                    bad_asn_and_pl += 1
                    v4_invalid += 1
                    v4_bw_invalid += relay.bw
                    if ml == pl: v4_mlpl += 1
                elif relay.asn[0] != relay.ipv4_roa[3]:
                    # check if asn from website mathces the asn from roa csv file
                    print("invalid asn mismatch")
                    if relay.asn[0] in invalids:
                        invalids[relay.asn[0]][1] += 1
                    else:
                        invalids.setdefault(relay.asn[0], [0, 1, 0])
                    bad_asn += 1
                    v4_invalid += 1
                    v4_bw_invalid += relay.bw
                    if ml == pl: v4_mlpl += 1
                elif int(float(pre_len)) > int(float(ml)):
                    # check if prefix length greater than maximum length
                    print("invalid prefix not match")
                    if relay.asn[0] in invalids:
                        invalids[relay.asn[0]][2] += 1
                    else:
                        invalids.setdefault(relay.asn[0], [0, 0, 1])
                    bad_pl += 1
                    v4_invalid += 1
                    v4_bw_invalid += relay.bw
                    if ml == pl: v4_mlpl += 1
                else:
                    # if both length is within max range and the asn matches from the 2 sources, it is a valid roa
                    print("valid roa")
                    v4_covered += 1
                    v4_bw_covered += relay.bw
                    # max length == prefix length
                    if ml == pl:
                        v4_mlpl += 1
                        v4_mlpl_valid += 1
                    # max length distribution
                    # see how many relay has the same max length setting
 
        v4Protected.append((v4_covered/num_relays)*100)
        v4BWProtected.append((v4_bw_covered/nw_bandwidth)*100)
        v4ProtectedTight.append((v4_mlpl/num_relays)*100)
        validROA.append((v4_covered/(v4_invalid+v4_covered))*100)
    plt.xlabel('Date')
    plt.ylabel('Percentage')
    
    x = range(len(months))

    plt.plot(x,v4Protected, label = "Percent IPv4 Protected Relay")
    plt.plot(x, v4BWProtected, label = "Percent Bandwidth IPv4 Protected Relay")
    plt.plot(x,v4ProtectedTight,label = "Percent IPv4 Protected Relay (Tight ml == pl)")
    plt.plot(x, validROA, label = "Percent of Valid ROA")

    plt.xticks(x, months, rotation ='vertical')
    plt.legend(bbox_to_anchor=(0, 1.02, 0.8, 0.3), loc="upper center", ncol=1)
    if guardsOnly:
        plt.savefig('GuardOnlyROACoverage_v4.png',bbox_inches='tight')
    else:
        plt.savefig('AllRelaysROACoverage_v4.png',bbox_inches='tight')

def graph_roa_multi_months_v6(months, guardsOnly):
    """
    sample call:
    python3 graph_multi_months_roa.py "2021-01-01-00, 2021-02-01-00, 2021-03-01-00, 2021-04-01-00,2021-05-01-00,2021-06-01-00,2021-07-01-00,2021-08-01-00,2021-09-01-00,2021-10-01-00,2021-11-01-00,2021-12-01-00,2022-01-01-00,2022-02-01-00,2022-03-01-00,2022-04-01-00,2022-05-01-00,2022-06-01-00,2022-07-01-00,2022-08-01-00,2022-09-01-00,2022-10-01-00,2022-11-01-00,2022-12-01-00,2023-01-01-00,2023-02-01-00,2023-03-01-00,2023-04-01-00,2023-05-01-00, 2023-06-01-00, 2023-07-01-00, 2023-08-01-00, 2023-09-01-00, 2023-10-01-00, 2023-11-01-00, 2023-12-01-00, 2024-01-01-00, 2024-02-01-00, 2024-03-01-00, 2024-04-01-00, 2024-05-01-00" n n    
    """
    validROA_v6 = []
    v6Protected = []
    v6BWProtected = []
    v6ProtectedTight = []

    for month in months:
        path = "../processed/" + month.strip() + "-processed.pickle"
        with open(path, 'rb') as f2:
            relays = pickle.load(f2)
        if guardsOnly:
            relays = guards(relays)


        bad_as_set = 0
        nw_bandwidth = 0
        nw_bandwidth_v6 = 0
        v6_bw_invalid = 0
        v6_invalid = 0
        bad_pl = 0
        invalids = dict()
        bad_asn_and_pl = 0
        bad_asn = 0   
        v6_covered = 0
        v6_bw_covered = 0
        v6_mlpl = 0
        v6_mlpl_valid = 0
        num_relays_v6 = 0
        for relay in relays:
            # bandwidth, num guards
            # count relays with ipv6
            if relay.ipv6 is not None:
                num_relays_v6 += 1
                nw_bandwidth_v6 += relay.bw    

            if relay.ipv6_roa is not None and relay.ipv6_prefix is not None:  # roa = [net(IPv4Network), max length(str), prefix length(str), asn]
                pre_len = relay.ipv6_prefix.split('/')[1]
                # e.g. 142.4.192.0/19 the above code will get the number after "/"
                # max length
                # print("what is ipv6 roa = ", relay.ipv6_roa)
                # print("what is ipv6 prefix = ", relay.ipv6_prefix)
                # print("what is ipv6 asn = ", relay.ipv6_asn)
                ml = relay.ipv6_roa[1]    # max length of ROA network
                pl = relay.ipv6_roa[2]    # prefix length of ROA network
                # if max length is not set use prefix length
                if ml == '':
                    ml = pl
                # check if invalid
                
                # check if there is an roa and its validity
                if len(relay.ipv6_asn) > 1:
                    # relay.asn return a list supposedly with 1 entry which is the asn
                    # make sure the format is valid, inherented this format from get_prefix_and_asn() in util.py
                    print("invalid multi asn v6")
                    bad_as_set += 1
                    v6_invalid += 1
                    v6_bw_invalid += relay.bw

                elif relay.ipv6_asn[0] != relay.ipv6_roa[3] and int(float(pre_len)) > int(float(ml)):
                    # compare asn obtained from requesting website and the roa file
                    # relay.asn[0] obtain from web, relay.ipv4_roa[3] obtained from ROA file
                    # relay.ipv4_roa =  [IPv4Network('142.4.192.0/19'), '19', '19', '16276']
                    #                   [net(IPv4Network), max length(str), prefix length(str), asn]
                    # check if prefix is longer than max length
                    # defining a max length would be vulnerable to a more specific BGP hijack?

                    print("invalid both asn mismatch and prefix not match")
                    if relay.ipv6_asn[0] in invalids:
                        invalids[relay.ipv6_asn[0]][0] += 1
                    else:
                        invalids.setdefault(relay.ipv6_asn[0], [1, 0, 0])
                    bad_asn_and_pl += 1
                    v6_invalid += 1
                    v6_bw_invalid += relay.bw
                    if ml == pl: v6_mlpl += 1
                elif relay.ipv6_asn[0] != relay.ipv6_roa[3]:
                    # check if asn from website mathces the asn from roa csv file
                    print("invalid asn mismatch")
                    if relay.ipv6_asn[0] in invalids:
                        invalids[relay.ipv6_asn[0]][1] += 1
                    else:
                        invalids.setdefault(relay.ipv6_asn[0], [0, 1, 0])
                    bad_asn += 1
                    v6_invalid += 1
                    v6_bw_invalid += relay.bw
                    if ml == pl: v6_mlpl += 1
                elif int(float(pre_len)) > int(float(ml)):
                    # check if prefix length greater than maximum length
                    print("invalid prefix not match")
                    if relay.ipv6_asn[0] in invalids:
                        invalids[relay.ipv6_asn[0]][2] += 1
                    else:
                        invalids.setdefault(relay.ipv6_asn[0], [0, 0, 1])
                    bad_pl += 1
                    v6_invalid += 1
                    v6_bw_invalid += relay.bw
                    if ml == pl: v6_mlpl += 1
                else:
                    # if both length is within max range and the asn matches from the 2 sources, it is a valid roa
                    print("valid roa")
                    v6_covered += 1
                    v6_bw_covered += relay.bw
                    # max length == prefix length
                    if ml == pl:
                        v6_mlpl += 1
                        v6_mlpl_valid += 1
                    # max length distribution
                    # see how many relay has the same max length setting
        # print("month = ", month)
        # print("what is v6 covered = ", v6_covered)
        # print("what is v6 invalid = ", v6_invalid)
        # if month == "2022-02-01-00":
        #     print(num_relays_v6)
        #     time.sleep(100000)
        v6Protected.append((v6_covered/num_relays_v6)*100)
        v6BWProtected.append((v6_bw_covered/nw_bandwidth_v6)*100)
        v6ProtectedTight.append((v6_mlpl/num_relays_v6)*100)
        validROA_v6.append(v6_covered/(v6_invalid+v6_covered)*100)
    plt.xlabel('Date')
    plt.ylabel('Percentage')
    
    x = range(len(months))
    if guardsOnly:
        plt.title("ROA Coverage for IPv6 Guard Relays")
    else:
        plt.title("ROA Coverage for All IPv4 Relays")

    plt.plot(x,v6Protected, label = "Percent IPv6 Protected Relay")
    plt.plot(x, v6BWProtected, label = "Percent Bandwidth IPv6 Protected Relay")
    plt.plot(x,v6ProtectedTight,label = "Percent IPv6 Protected Relay (Tight ml == pl)")
    plt.plot(x, validROA_v6, label = "Percent of Valid ROA ipv6")
    plt.xticks(x, months, rotation ='vertical')
    plt.legend(bbox_to_anchor=(0, 1.02, 0.8, 0.3), loc="upper center", ncol=1)
    if guardsOnly:
        plt.savefig('GuardOnlyROACoverage_v6.png',bbox_inches='tight')
    else:
        plt.savefig('AllRelaysROACoverage_v6.png',bbox_inches='tight')
        
            
            
        
def check_client():
    file =  open('./typicalTOR1000Clients2023.pickle', 'rb') #open a file where a list of ASN with ROV is kept 
    clients = pickle.load(file)
    roarov = 0
    roa = 0
    rov = 0
    neither = 0
    for c in clients:
        if check_rov(c.AS.ASN) and c.roaCovered:
            roarov += 1
        elif check_rov(c.AS.ASN):
            rov += 1
        elif c.roaCovered:
            roa += 1
        else:
            neither += 1
    print("roarov, roa, rov, neither")
    print(roarov, roa, rov, neither)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))