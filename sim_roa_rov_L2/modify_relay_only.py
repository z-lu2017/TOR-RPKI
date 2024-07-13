import yaml
import pandas as pd
import random
import itertools
from random import shuffle

df = pd.read_csv("basic_info_relay.csv")
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
            print(data['hosts'][entry]['processes'][0]['args'])


# update the yaml file with the selected relays as the new baseline: unit: kilobytes/second -> kilobits
for entry in data['hosts']:
    data['hosts'][entry]['RoarovStatus'] =  '-1'
    if 'guard' in entry:
        ind = ips.index(data['hosts'][entry]['ip_addr'])
        b = bws[ind]
        data['hosts'][entry]['bandwidth_down'] = str(b) + " kilobit"
        data['hosts'][entry]['bandwidth_up'] = str(b) + " kilobit"
        data['hosts'][entry]['RoarovStatus'] =  str(status[ind])
    else:
        pass

# output final yaml with the update status
fnameout = 'shadow-out.config.yaml'
with open(fnameout, 'w') as yaml_file:
     yaml_file.write( yaml.dump(data, default_flow_style=False))

print("Done with relay modification")
