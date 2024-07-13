import os
import pickle
from datetime import timedelta, datetime
from random import randrange, choices, sample
import matplotlib.pyplot as plt
import ipaddress
import csv
import numpy as np
from ASNrov import *

# constants, using suggested values from 271
MAX_SAMPLE_THRESHOLD = .2                           # percent
MAX_SAMPLE_SIZE = 60
MIN_FILTERED_SAMPLE = 20
GUARD_LIFETIME = 120                                # days
REMOVE_UNLISTED_GUARDS_AFTER = timedelta(days=20)   # days
N_PRIMARY_GUARDS = 3

# global variables
GUARDS = set()          # set of all guards in current consensus
CUR_GUARDS = dict()     # current guard relays in use (Guard, num_clients)
WGD = 0                 # bandwidth weight for guard exits
WGG = 0                 # bandwidth weight for guards
file =  open('ASNwROV.pickle', 'rb') #open a file where a list of ASN with ROV is kept 
ROVset = pickle.load(file)
file.close()

class Relay:
    # '''Relay class

    # Attributes
    # ----------
    # fp : string
    #     Fingerprint (unique id)
    # ip : string
    #     IP address
    # ipv6 : string
    #     if relay has IPv6 address, ipv6 == (string) ipv6 address
    #     if relay doesn't have an IPv6 address, ipv6 == ''
    # bw : int
    #     Bandwidth
    # is_guard : bool
    #     True if has 'Guard' flag
    # is_exit : bool
    #     True if has 'Exit' flag
    # '''
    """
    relay object used to store information extracted from consensus file 
    """
    def __init__(self, fp, digest, ip):
        # relay info
        self.fp = fp
        self.ip = ip
        self.digest = digest
        self.ipv6 = ''
        self.bw = 0
        self.is_guard = False
        self.is_exit = False
        self.or_addresses = None

        # preprocessing ROA coverage info
        self.asn = None
        self.ipv4_prefix = None
        self.ipv4_roa = None   # if roa, = [net(IPv4Network), max length(str), prefix length(str), asn]
        self.ipv6_asn = None
        self.ipv6_prefix = None
        self.ipv6_roa = None
        self.rovCovered = None

        # persistently record
        self.sampled_on = datetime(1, 1, 1, 0)
        self.listed = True
        self.unlisted_since = datetime(1, 1, 1, 0)

    def __eq__(self, other):
        return self.fp == other.fp

    def __str__(self):
        return self.fp

    def __hash__(self):
        return hash(self.fp)


class Client:
    # '''Client class for simulating selection algorithm'''
    """
    client object to run simulation on selection algorithm. Has AS, IP address attribute to reflect a more realistic simulation. 
    check add_sampled_guards() to see the implementation of discount and matching selection alforithm. 
    """
    def __init__(self, selection_algo):
        self.sampled_guards = set()   # nodes that have been listed as a guard at some point
        self.primary_guards = list()  # subset of filtered guards containing N_PRIMARY_GUARDS elements
        self.guard_list = list()
        self.origin = None #country 
        self.AS = None #the AS object, need to do AS.ASN to get the actual number 
        self.selection_algo = selection_algo # relay select method: vanilla, discount(e.g. 0.7), matching
        self.ipaddress = None #in dotted notation
        self.prefix = None #get the ip prefix, e.g. 31.149.0.0/16
        self.roa = None #[ip network obj, maxlen, prefixlen, asn]
        self.roaCovered = None #true or false value indicating roa's validity
        self.rovCovered = None
        self.rovDiscount = 0.2
        self.roaDiscount = 0.1
        self.neitherDiscount = 1
        self.matchedRelay = None
    # call each consenses
    def on_consensus(self, t):
        self.update_sampled_guards(t)
        self.update_primary_guards()

    # updates listed and unlisted_since for each guard in sampled_guards; adds and removes if needed
    def update_sampled_guards(self, t):
        # update listed and unlisted_since
        for sg in self.sampled_guards:
            if sg not in GUARDS:
                if sg.listed:
                    sg.listed = False
                    sg.unlisted_since = t       # this val should be randomized)
            else:
                if not sg.listed:
                    sg.listed = True
                    sg.unlisted_since = datetime(1, 1, 1, 0)

        # remove sampled guards
        self.remove_sampled_guards(t)

        # add sampled guards
        if len(self.sampled_guards) < MIN_FILTERED_SAMPLE:   # 2020 08 23  MIN_FILTERED_SAMPLE instead of MAX_SAMPLED_SIZE
            self.add_sampled_guards(t)

    # HELPER FUNCTION remove guards from sampled_guards
    def remove_sampled_guards(self, t):
        for g in self.sampled_guards.copy():
            if (not g.listed) and ((t - g.unlisted_since) > REMOVE_UNLISTED_GUARDS_AFTER):
                self.sampled_guards.remove(g)
            elif (t - g.sampled_on) > timedelta(days=GUARD_LIFETIME):
                self.sampled_guards.remove(g)

    # HELPER FUNCTION pick entry at random from GUARDS - sampled_guards, weighted by bandwidth, add to sampled_guards
    def add_sampled_guards(self, t):
        possible = list(GUARDS.difference(self.sampled_guards))
        weights = list()
        discount = 1

        #based on command line input, decide the guard selection method
        if self.selection_algo == "vanilla":
            discount = 1 
        elif self.selection_algo == "matching":
            discount = "NA" #match ROA and ROV on client and relay side
        else:
            try: 
                discount = float(self.selection_algo) #use discount method to increase relay with ROA to be selected
            except:
                print("invalid relays selection method input")
        # calculate weight of each guard
        #using the discount method
        if discount != "NA":
            for pg in possible:
                if pg.is_exit:  # if pg is an exit
                    if pg.ipv4_roa != None:
                        w = int(pg.bw * WGD)  # wgd, g+e in g position
                    else:
                        w = int(pg.bw * WGD)*discount
                else:
                    if pg.ipv4_roa != None:
                        w = int(pg.bw * WGG)  # wgg, g in g position
                    else:
                        w = int(pg.bw * WGG)*discount
                weights.append(w)
        else:
            
            #check the 4 cases of the matching method

            #ROV and ROV & ROV case, discount all non ROA relay by 0.1
            if check_rov(self.AS.ASN) or ((check_rov(self.AS.ASN) and self.roaCovered)): 
                for pg in possible:
                    if pg.is_exit:
                        consensusWeight = WGD
                    else:
                        consensusWeight = WGG
                    if pg.ipv4_roa != None:
                        w = int(pg.bw * consensusWeight)
                    else:
                        w = int(pg.bw * consensusWeight)*self.rovDiscount
                    weights.append(w)

            #ROA case, discount non-rov relay by 0.6
            elif self.roaCovered:
                for pg in possible:
                    if pg.is_exit:
                        consensusWeight = WGD
                    else:
                        consensusWeight = WGG
                    if pg.asn != None:
                        cgASN = pg.asn[0]
                    else:
                        cgASN = None
                    if check_rov(cgASN):
                        w = int(pg.bw * consensusWeight)
                    else: 
                        w = int(pg.bw * consensusWeight)*self.roaDiscount
                    weights.append(w)

            #neither case, discount all relay with ROA or ROV by 0.1
            elif not self.roaCovered and not check_rov(self.AS.ASN):
                for pg in possible:
                    if pg.is_exit:
                        consensusWeight = WGD
                    else:
                        consensusWeight = WGG
                    if pg.asn != None:
                        cgASN = pg.asn[0]
                    else:
                        cgASN = None
                    if not check_rov(cgASN) and pg.ipv4_roa == None:
                        w = int(pg.bw * consensusWeight)
                    else:
                        w = int(pg.bw * consensusWeight)*self.neitherDiscount
                    weights.append(w)
            
                



        n = MAX_SAMPLE_SIZE - len(self.sampled_guards)

        sg = choices(possible, weights, k=n)
        sg2 = []
        for g in sg:
            g.sampled_on = rand_date(t, (GUARD_LIFETIME / 10))
            sg2.append(g)
        self.sampled_guards.update(sg2)
    
    # def total_exit_available(self):
    #     possible = []
    #     for e in EXIT:
    #         # print(e)
    #         if e.fp != self.guard_list[-1].fp: 
    #             if not check16(self.guard_list[-1].ip, e.ip):
    #                 possible.append(e)
    #     return possible

    # update primary guards
    def update_primary_guards(self):
        # remove if not in sampled_guards or if not listed
        for p in self.primary_guards.copy():
            if p not in self.sampled_guards:
                self.primary_guards.remove(p)
            else:
                for sg in self.sampled_guards:
                    if sg.fp == p.fp:
                        if not sg.listed:
                            self.primary_guards.remove(p)
                        break

        # randomly choose new guards from sampled guards
        if len(self.primary_guards) < N_PRIMARY_GUARDS:
            n = N_PRIMARY_GUARDS - len(self.primary_guards)
            s = set([i for i in self.sampled_guards if i.listed])
            d = s.difference(set(self.primary_guards))
            pgs = sample(list(d), k=n)
            for pg in pgs:
                if pg in self.primary_guards:
                    print('already in primary guards')
                self.primary_guards.append(pg)

        # if guard_list is empty AKA first consensus
        if not bool(self.guard_list):
            # add new guard relay to client's guard list
            self.guard_list.append(self.primary_guards[0])
            # add new guard to CUR_GUARDS
            CUR_GUARDS.setdefault(self.guard_list[-1].fp, 0)
            CUR_GUARDS[self.guard_list[-1].fp] += 1
            return

        # if primary guard at 0 idx removed, update self.guard_list
        elif self.guard_list[-1].fp != self.primary_guards[0].fp:
            # decrement CUR_GUARDS counter and remove if == 0
            CUR_GUARDS[self.guard_list[-1].fp] -= 1
            if CUR_GUARDS[self.guard_list[-1].fp] == 0:
                CUR_GUARDS.pop(self.guard_list[-1].fp)

            # add new guard relay to client's guard list
            self.guard_list.append(self.primary_guards[0])

            # add new guard to CUR_GUARDS
            CUR_GUARDS.setdefault(self.guard_list[-1].fp, 0)
            CUR_GUARDS[self.guard_list[-1].fp] += 1

        # update bw of client's guard
        cur_updated = [i for i in GUARDS if i.fp == self.guard_list[-1].fp]
        if len(cur_updated) == 0:
            print('this client\'s primary guard isn\'t in the curent consensus')
            return
        self.guard_list[-1].bw = cur_updated[0].bw

class AS:
    """
    AS object to store ASN, origin and helper attribute when analyzing AS and IP. 
    """
    def __init__(self, ASN = 0, origin = "NA", numIPv4 = 0):
        self.ASN = ASN 
        self.origin = origin
        self.numIPv4 = 0
        self.prevNetwork = None
        self.prevMin = None
        self.prevMax = None
        self.prefixes = []
        

    def __eq__(self, obj):
        return self.ASN == obj.ASN

    def __hash__(self):
        return hash(self.ASN)


def load_consensus(p, year, month, date, hour):
    """Pulls relay data from processed consensus file"""
    # load .pickle file
    filename = p + year + '-' + month + '-' + date + '-' + hour + '-processed.pickle'
    print(filename )
    try:
        file = open(filename, 'rb')
    # if it doesn't exist, don't update GUARDS, WGD, WGG
    except FileNotFoundError:
        print('Consensus for ' + year + '-' + month + '-' + date + '-' + hour + ' doesn\'t exist.')
        return
    # update GUARDS, WGD, WGG
    GUARDS.clear()
    rs = pickle.load(file)
    gs = [r for r in rs if r.is_guard]
    GUARDS.update(gs)

    global WGD
    WGD = pickle.load(file)
    global WGG
    WGG = pickle.load(file)


def datespan(s, e, delta=timedelta(hours=1)):
    """Function to iterate through each hour in a given timespan"""
    # from https://stackoverflow.com/questions/153584/how-to-iterate-over-a-timespan-after-days-hours-weeks-and-months
    cd = s
    while cd < e:
        yield cd
        cd += delta


def check16(ip1, ip2):
    """
    helper function to check if 2 IP address belongs to the same /16 prefix 
    """
    ip1 = ip1.split('.')
    ipBin1 = ""
    for oct in ip1:
        ipBin1 += '{0:08b}'.format(int(oct))
    
    ip2 = ip2.split('.')
    ipBin2 = ""
    for oct in ip2:
        ipBin2 += '{0:08b}'.format(int(oct))
    # print(ipBin1)
    # print(ipBin2)
    for i in range(0,16):
        if ipBin1[i] != ipBin2[i]:
            return False
    return True

def rand_date(now, interval):
    """Random time b/t now and INTERVAL in the past; parameters: now (datetime); interval (num. days)"""
    num_hours = interval * 24
    rand_hour = randrange(num_hours)
    return now - timedelta(hours=rand_hour)


def tsplot(x, y, ax, n=20, percentile_min=1, percentile_max=99, color='r', plot_mean=True, plot_median=False, line_color='k', **kwargs):
    """Plots average and two percentile bands (IQR & 90%) on axis ax"""
    # calculate the lower and upper percentile groups, skipping 50 percentile
    perc1 = np.percentile(y, np.linspace(percentile_min, 50, num=n, endpoint=False), axis=0)
    perc2 = np.percentile(y, np.linspace(50, percentile_max, num=n + 1)[1:], axis=0)
    # alpha
    if 'alpha' in kwargs:
        alpha = kwargs.pop('alpha')
    else:
        alpha = 1 / n
    # fill lower and upper percentile groups
    for p1, p2 in zip(perc1, perc2):
        ax.fill_between(x, p1, p2, alpha=alpha, color=color, edgecolor=None)
    if plot_mean:
        ax.plot(x, np.mean(y, axis=0), color=line_color)
    if plot_median:
        ax.plot(x, np.median(y, axis=0), color=line_color)

# slow function ?
def calculate_total_bw(clients):
    """Calculates the total network bandwidth at a given hour"""
    total_bw = 0
    for cg in CUR_GUARDS:
        for client in clients:
            if client.guard_list[-1].fp == cg:
                total_bw += client.guard_list[-1].bw
                break
    return total_bw

def check_rov(asn):
    """use ROV set to check if an ASN if inside the covered set"""
    global ROVset
    return asn in ROVset

