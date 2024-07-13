from bs4 import BeautifulSoup
import requests
import pickle

def get_ROV_data(files):
    '''
    extracts the AS that performs ROV from https://rov.rpki.net/. The input are 
    a list of filenames that contains the html of the table of ROV from https://rov.rpki.net/. 
    
    :param files: (string) a list of filenames that contains the html of the ROV ASN 

    :return: (pickle file) a pickled file saved to current directory that contains all the ASN of all AS that performs ROV. 
    '''
    #copy tbody tag within table id tag from https://rov.rpki.net/ into txt file
    #this function parses html copied from the above site and extract all the ASN with ROV coverage into a set 
    #dump into a pickle
    #sample usage: get_ROV_data(['page.txt', 'page2.txt', 'page3.txt'])
    ROVList = []
    #open each file in for loop
    for f in files:
        file = open(f)
        #use external library bs4 to find all tr tag 
        soup = BeautifulSoup(file, 'html.parser')
        for i in soup.findAll('tr'):
            #iterate through all tr tag, find td tag within and index the part that has the ASN and append 
            #to list
            ROVList.append(str(i.findAll('td')[1])[4:-5])
    
    #pickled the returned list into a set 
    with open('ASNwROV.pickle', 'wb') as pf:
        pickle.dump(set(ROVList), pf)
    

get_ROV_data(['page1.txt', 'page2.txt'])

