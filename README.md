# TOR-RPKI_Siyang
This python simulator simultates the TOR’s relay selection process. The consensus file from Tor Metrics are used to simulate to network environment, including the relay status and bandwidth. Then, the simulator creates client object to mimic the relay selection process in actual TOR network. ROA/ROV coverage for guard relay and ROA-ROV matching connection coverage are extracted from these simulations. The flow diagram below shows the work flow of the python simulator in creating guard selection simulation, record ROA/ROV coverage etc. Look at full documentation [here.](https://siyangsun2001.github.io/TOR-RPKI_Siyang/_build/html/index.html)
## Mini Tutorial
Preprocessing Consensus:
The consensus file we downloaded from Tor Metrics need to be parsed and checked for RPKI coverage for future analysis. We parse these file once and pickle them (python’s library for converting object into byte string) for later use, so we don’t have to process the raw data everytime. 

0. Install [virtual environment](https://www.cs.virginia.edu/wiki/doku.php?id=linux_python_tips&s[]=source&s[]=local&s[]=env&s[]=bin&s[]=activate) if neded, and download all neccessary libraries.
1. Download TOR Consensus file from TOR Metrics and store in the  tor-rpki/archive folder and de-compress it. 
2. Download ROA data corresponding to the same month of consensus here, and de-compress the folder. 
3. Go to the output folder within the de-compressed ROA folder and copy the only .csv file into the tor-rpki folder 
4. !!(ignore this step, updated code to take in different format)!!Run convertData.py to convert the .csv file into the readable form 
5. Run preprocessConsensus.py fill in the time period corresponding to the consensus file and also put the whole path to the .csv file for ROA validation. If this is your first time running a consensus that is half a year away from the previous consensus, you would want to put make_pickle = True, existing_file = False in the pre_asn function. In this way, it makes a new pickle file for the  ip -> asn map so later consensus could use this more recent file to achieve a faster runtime 
