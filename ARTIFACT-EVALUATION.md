# Artifact Appendix

Paper title: RPKI-based Location-Unaware Tor Guard Relay Selection Algorithms

Artifacts HotCRP Id: 22

Requested Badge: Reproduced

## Description
The artifact provided includes all data, source code and simulation scripts used in the paper.

### Security/Privacy Issues and Ethical Concerns (All badges)
N/A

## Basic Requirements (Only for Functional and Reproduced badges)
All scripts have been tested on a VM with 1 vcpu and 16 GB of RAM. The estimated total time to run provided scripts should not exceed 72 hours. The estimated storage requirement is at least 100 GB.

### Hardware Requirements
For artifact evaluation, our code uses a portion of the total data (2 weeks out of 4 months) to demonstrate functionality. Minimum storage required for running the experiment using 2 weeks of data is 100 GB and the total storage required for running the experiement using 4 months of data is 308 GB.

### Software Requirements
All required packages are listed on the github page and are publicly available. All required packages are installed on the VM.

### Estimated Time and Storage Consumption
The estimated time to run all provided scripts should not exceed 72 hours and storage requirement is at least 100 GB.

## Environment 
All dataset sources are listed on the github page and are publicly available. We also include a link to all the data we used. Install all required packages listed on the github page. The VM is pre-setup for the evaluation.

### Accessibility (All badges)
All source code are on the following github repo: https://github.com/z-lu2017/TOR-RPKI.git. Use commit ID aa3c1b6 for evaluation.
All data and VM can be found here: https://torstudy.cs.virginia.edu/

### Set up the environment (Only for Functional and Reproduced badges)
Clone git repo and install required packages.

```bash
git clone https://github.com/z-lu2017/TOR-RPKI.git
or git pull if the directory already exists
pip3 install pyasn requests pytz pandas scipy matplotlib pyscipopt lxml bs4
```

### Testing the Environment (Only for Functional and Reproduced badges)
To check if all required packages have been installed, run
```bash
python envtest.py
```

The expected print messages are "[package name] has been imported".
If any package is missing, it will print "can't find the [package name]".
All required modules have been installed on the provided VM.

For Shadow and tornettools environment testing, please check their official page linked below since they already have a thorough test suite.

## Artifact Evaluation (Only for Functional and Reproduced badges)
This section includes all the steps required to evaluate your artifact's functionality and validate your paper's key results and claims.
Therefore, highlight your paper's main results and claims in the first subsection. And describe the experiments that support your claims in the subsection after that.

### Main Results and Claims
List all your paper's results and claims that are supported by your submitted artifacts.

#### Main Result 1: Tor relay ROA coverage rate
ROA measurement suggests high IPv4 ROA coverage and low IPv6 ROA coverage.
Section 3.2

#### Main Result 2: Discount selection algorithm
Discount selection algorithm improves the percentage of clients with ROA covered guard under various discount factors. The best combination of discount factor and load factors vary overtime. 
Section 4

#### Main Result 3: Matching selection algorithm
Matching selection algorithm significantly increases the percentage of relay-client pairs with matched ROA & ROV.  
Section 5.1-5.3

#### Main Result 4: Both proposed algorithms does not produce significant overhead
Shadow simulations show no significant overhead when the algorithms are run on a larger, network scale.
Section 5.4

#### Main Result 5: Deployment concern
Realistic concerns such as churn and and scalablity are measured to demonstrate the proposed methods are realistically deployable.
Section 6

### Experiments 
List each experiment the reviewer has to execute. Describe:
 - How to execute it in detailed steps.
 - What the expected result is.
 - How long it takes and how much space it consumes on disk. (approximately)
 - Which claim and results does it support, and how.

To run all experiments, please maintain the following folder structure:

TOR-RPKI/

  - archive/

  - archive_pickles/
  
  - clients_daily/
  
  - mergedROAs/
  
  - processed/
  
  - routeviews/

  - sim_roa_rov_L2/

      - scripts
      
      ....

All python simulations scripts should be run from the folder sim_roa_rov_L2, while all Shadow simulation scripts are to be run from tornetools_custom folder.

#### Experiment 1: Measure Tor relay ROA coverage
This experiment measures the ROA coverage percentage and produce Figure 1 and Figure 7 in the paper.
```bash
python3 graph_multi_months_roa.py y y
```
The first parameter indicates whether to measure guard relays only and the second parameter indicates whether it is v4(y) or v6(n).
This experiment supports main result 1. 
Expected runtime is 10 minutes and no additional storage requirement.
The output files are *GuardOnlyROACoverage_v4.png*, *AllRelaysROACoverage_v4.png*, *GuardOnlyROACoverage_v6.png* and *AllRelaysROACoverage_v6.png*.

#### Experiment 2: Perform discount selection
This experiment performs the discount selection algorithm on data using 2024/05 and produce three outputs. sim_discount.py runs two functions run_sim() and sim_load(). 

```bash
python3 sim_discount.py
```
run_sim() simulates the discount selection algorithm on 1 million clients and outputs file output-discount.csv with the format date/discount/roa_coverage_before/roa_coverage_after. 
sim_load() simulates the relationship between load factor and discount factor and outputs two files output-discount-load.csv and output-discount-load-optimal.csv. 
output-discount-load.csv outputs the various load utilization under various combination of discount and load factor and is in the format date/discount/load/utilizations. 
output-discount-load-optimal.csv reports the best combo (aka kinks in the graphs) in the format date/discount/load.
For artifact evaluation, we only included data for 2024/05 to save space and the scripts are set up to run only that data. If more storage is available, the scripts can be easily changed by altering the months_final(line 973 and 1085) and years(line 967 and 1078) in the code.
This experiment supports main result 2.

Expected runtime is 1 hour per datapoint.
The output files are *output-discount.csv*, *output-discount-load.csv", and *output-discount-load-optimal.csv*.

#### Experiment 3: Perform matching selection 
This experiment performs the matching selection algorithm on data using 2024/05 and produce one output. sim_matching.py runs the matching selection algorithm on 1 million clients using various ROV source and outputs file output-matching-202405.csv with the format date/ROV_data/matched_before/matched_after. 
The default date used is May 2024.

```bash
python3 sim_matching.py
```
This experiment supports main result 3.
Expected runtime is 6 hours, among which 2 hours is spent on client generation.
The output files are *output-matching-202405.csv*.

#### Experiment 4: Perform matching selection with churn 
This experiment performs the matching selection algorithm with the consideration of client churn. 
The default matching_select.py generates 1 million clients using geographic distribution from Tor Metrics and stores the client objects in the clients_daily folder. If clients objects are downloaded directly, run matching_select_new.py to skip the client generation step. 
matching_select_plain.py is the version that performs matching without considering churn and uses the same client distribution from stored clients objects.
For artifact evaluation, we only included data for 14 days, 01/01/2024-01/14/2024 to demonstrate functionality. The whole dataset will produce intermediate data larger than 180 GB. If more storage is available, the scripts can be changed by altering start_date and end_date in the last two lines.

```bash
python3 matching_select_plain.py
```
and 

```bash
python3 matching_select_new.py
```

This experiment supports main result 5.
Expected runtime is 2 hours per datapoint for matching_select and 1 hour per datapoint for matching_select_new and matching_select_plain.
The output files are *output-matching-$method$date.csv*. For example, running *matching_select_plain.py* with the date range 2024-01-01 to 2024-01-14 will produce an output file named *output-matching-new$date* for each day with the $date variable being the date for that run. This is also the case for the other methods.


For experiment 2, 3 and 4, all final results can be plotted by running 

```bash
python3 plot.py
```
Make sure plotting data exist before plotting by running at least one experiment from 2-4. 
Plotting produces figure 2-6 from the paper.


#### Experiment 5: Shadow simulation 
This experiment performs Shadow simulation on all selection algorithms. All experiments are run with Shadow v3.2.0.
Three simulations are performed, vanilla, discount and matching. tor-vanilla, tor-discount, tor-matching are precompiled executables for each algorithm. The modified Tor source code are in tor-modified folder.
When running a simulation, copy the corresponding executable to /home/ubuntu/.local/bin/ and overwrite as tor. E.g.

```bash
sudo cp /home/ubuntu/tor-discount /home/ubuntu/.local/bin/tor
```

Custom Tor configurations for Shadow:
To run our modified Tor, additional data are prepared:
* All files need to be put in folder /usr/local/share/tor
* ROA database: The file used to check ROA. Original data from mergedROAs folder. In the VM, file 20240501.csv is used.
* ROV database: The file used to check ROV. Original data from any of the source listed on github. In the VM, ASNwROV.csv is used.
* Routeview data: The routeview file matching the data from the ROA database. Original data from routeviews folder. In the VM, file routeviews-rv2-20240501-1000.pfx2as is used.
It is important that data files match, i.e. the ROA database and the routeview data are close in date.

The simulation can be setup by running 
```bash
/home/ubuntu/tornettools_custom/generate.sh
```
This script uses tornettools to generate 10 times, each time a different network with clients that matches with our desired ROA/ROV distribution. Randomness comes from two sources: a. RNG-seed from Shadow; b. our random sampling for clients with the desired ROA/ROV distribution
Each run, the vanilla network is first generated, and then copied to create the discount and matching network. This is to ensure within the same run, all algorithms are run on the same network so we can compare results on the same basis.
Then all data across all 10 runs are aggregated by running 

```bash
/home/ubuntu/tornettools_custom/aggregate.sh
```

The aggregate script finds all data from all runs (search by filename with keyword "matching", "discount", "vanilla") and computes the mean for the selected measurements.

Run 
```bash
/home/ubuntu/tornettools_custom/graph.sh
```
To plot the simulation results.

**All scripts provided uses the old scale, i.e. 0.1, to show the way we run the original experiment. The memory required to finish simulations on such scale will be at least 440 GB** 

This experiment supports main result 4 and produces figure 5 in the paper.
Expected runtime is up to 12 hours per simulation and less than 2GB of storage per simulation.
The output: for each simulation, the results are stored in folder *shadow.data* under the simulation folder, and running ``` tornettools parse $simulation``` will produce a folder named *tornet.plot.data* with all the data used in the plotting under the simulation folder. Running ```graph.sh``` under the tornettools_custom folder will output all graphs in the folder named *out*.


## Limitations (Only for Functional and Reproduced badges)
Due to the large size of intermediate data, for experiment 2 and 4, we only included partial data. 
Due to the large memory requirement, experiment 5 is performed on a smaller scale (0.005) compared to the scale (0.1) used in our paper.

## Notes on Reusability (Only for Functional and Reproduced badges)
Our code provides a framework for integrating with other types of mechanisms against against additional routing attacks. See section 7.3 limitation and future integration in the paper for detail.
