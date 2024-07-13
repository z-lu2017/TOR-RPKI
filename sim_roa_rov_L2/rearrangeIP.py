import yaml
import pandas as pd
import random
import itertools
from random import shuffle

def calc(status, bandwidths):
    s = sum(bandwidths)
    s1 = 0
    s2 = 0
    s3 = 0
    s4 = 0
    for i in range(len(status)):
        if status[i] == 0:
            s1 += bandwidths[i]
        elif status[i] == 1:
            s2 += bandwidths[i]
        elif status[i] == 2:
            s3 += bandwidths[i]
        else:
            s4 += bandwidths[i]
    l = [s1/s, s2/s, s3/s, s4/s]
    return l

def diff(l1, l2):
    s = 0
    for i in range(len(l1)):
        s += (l1[i] - l2[i]) ** 2
    return s

# distribution from python optimization
num_dist = [0.28110, 0.47374, 0.10194, 0.14322]
bw_perc_dist = [0.26536, 0.48951, 0.087231, 0.15789]
totalbw = 75485470

# load in relay basic info
df = pd.read_csv("/home/ubuntu/basic_info_relay.csv")

both = df.loc[(df['roa'] == 1) & (df['rov'] == 1)]
roa = df.loc[(df['roa'] == 1) & (df['rov'] == 0)]
rov = df.loc[(df['roa'] == 0) & (df['rov'] == 1)]
neither = df.loc[(df['roa'] == 0) & (df['rov'] == 0)]

both_ip = both['ip'].tolist()
both_bw = both['bw'].tolist()
roa_ip = roa['ip'].tolist()
roa_bw = roa['bw'].tolist()
rov_ip = rov['ip'].tolist()
rov_bw = rov['bw'].tolist()
neither_ip = neither['ip'].tolist()
neither_bw = neither['bw'].tolist()

# calculate default yaml config count
count = 0
fname = 'shadow.config.yaml'
stream = open(fname, 'r')
data = yaml.load(stream, Loader=yaml.FullLoader)
for entry in data['hosts']:
    if 'guard' in entry:
        count = count + 1

print("a total of " + str(count) + " relays by default")

# read in default config and bandwidths
bws = []
status = []
best_bw = []
ips = []

# load in yaml config
fname = 'shadow.config.yaml'
stream = open(fname, 'r')
data = yaml.load(stream, Loader=yaml.FullLoader)

# update the yaml file with the selected relays as the new baseline: unit: kilobytes/second -> kilobits
for entry in data['hosts']:
    if 'guard' in entry:
            ip = data['hosts'][entry]['ip_addr']
            if ip in both_ip:
                 status.append(0)
                 ips.append(ip)
            elif ip in roa_ip:
                 status.append(1)
                 ips.append(ip)
            elif ip in rov_ip:
                 status.append(2)
                 ips.append(ip)
            else:
                 status.append(3)
                 ips.append(ip)
            bw = (int(data['hosts'][entry]['bandwidth_down'].replace(" kilobit", "")) + int(data['hosts'][entry]['bandwidth_up'].replace(" kilobit", "")))/2
            bws.append(bw)

l = calc(status, bws)
print("original perc = ", l)
s = diff(l, bw_perc_dist)
print("original diff = ", s)

best_s = s


for i in range(1000000):
    shuffle(bws)
    l = calc(status, bws)
    s = diff(l, bw_perc_dist)
    if s < best_s:
        best_s = s 
        best_l = l
        best_bw = bws

print("final best s = ", best_s)
print("final best l = ", best_l)
# print("final best p = ", best_bw)

# update the yaml file with the selected relays as the new baseline: unit: kilobytes/second -> kilobits
for entry in data['hosts']:
    if 'guard' in entry:
        ind = ips.index(data['hosts'][entry]['ip_addr'])
        b = int(best_bw[ind])
        data['hosts'][entry]['bandwidth_down'] = str(b) + " kilobit"
        data['hosts'][entry]['bandwidth_up'] = str(b) + " kilobit"
    else:
        pass


with open(fname, 'w') as yaml_file:
     yaml_file.write( yaml.dump(data, default_flow_style=False))

print("Done with relay modification")
