import yaml
import pandas as pd
import random

fname = 'shadow.config.yaml'
stream = open(fname, 'r')
data = yaml.load(stream, Loader=yaml.FullLoader)

# remove roa and rov property for shadow
for entry in data['hosts']:
    try:
        del data['hosts'][entry]['roa'] 
        del data['hosts'][entry]['rov']
    except:
        pass

with open(fname, 'w') as yaml_file:
     yaml_file.write( yaml.dump(data, default_flow_style=False))