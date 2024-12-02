import requests
import pandas as pd
import glob
import os
import lzma

def getROA():
    BASE_URL = "https://ftp.ripe.net/rpki"
    REGIONS = ["afrinic.tal", "apnic.tal", "arin.tal", "lacnic.tal", "ripencc.tal"]
    MONTHS = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"]
    MONTHS2 = ["01", "02", "03", "04", "05"]
    #YEARS = ["2021", "2022", "2023", "2024"]
    YEARS = ["2022", "2023", "2024"]

    DAYS1 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31']
    DAYS2 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30']
    DAYS3 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28']
    DAYS4 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29']

    for y in YEARS:
        if y == "2024":
            MONTHS_FINAL = MONTHS2
        else:
            MONTHS_FINAL = MONTHS
        for m in MONTHS_FINAL:
            if m == "01" or m == "03" or m =="05" or m=="07" or m=="08" or m =="10" or m=="12":
                days = DAYS1
            elif m == "02" and int(y) % 4 == 0:
                days = DAYS4
            elif m == "02" and int(y) % 4 != 0:
                days = DAYS3
            else:
                days = DAYS2
            
            for d in days:
                for r in REGIONS:
                    url = BASE_URL + "/" + r + "/" + y + "/" + m + "/" + d + "/roas.csv.xz"
                    resp = requests.get(url)
                    print("Getting ROA for year = " + str(y) + " month = " + str(m) + " day = " + str(d) + " for region = " + str(r))
                    with open("./ROAs" + "/" + r + "-" + y + "-" + m + "-" + d + ".csv.xz", "wb") as f:
                        f.write(resp.content)


def mergeROAs():
    REGIONS = ["afrinic.tal", "apnic.tal", "arin.tal", "lacnic.tal", "ripencc.tal"]
    MONTHS = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"]
    MONTHS2 = ["01", "02", "03", "04", "05"]
    YEARS = ["2021", "2022", "2023", "2024"]

    DAYS1 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31']
    DAYS2 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30']
    DAYS3 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28']
    DAYS4 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29']

    for y in YEARS:
        if y == "2024":
            MONTHS_FINAL = MONTHS2
        else:
            MONTHS_FINAL = MONTHS
        for m in MONTHS_FINAL:
            if m == "01" or m == "03" or m =="05" or m=="07" or m=="08" or m =="10" or m=="12":
                days = DAYS1
            elif m == "02" and int(y) % 4 == 0:
                days = DAYS4
            elif m == "02" and int(y) % 4 != 0:
                days = DAYS3
            else:
                days = DAYS2
            
            for d in days:
                joined_list = glob.glob("./ROAs/*" + y + "-" + m + "-" + d + ".csv")
                if len(joined_list) > 0:
                    df = pd.concat(map(pd.read_csv, joined_list), ignore_index=True)
                    df = df[['ASN', 'IP Prefix', 'Max Length']]
                    df.to_csv("./mergedROAs/" +  y + m + d + ".csv", encoding='utf-8', index=False)


# create ROA directory
#os.mkdir("./ROAs")
#os.mkdir("./mergedROAs")

# grab all ROAs
getROA()
print("Done fetching all ROAs")

# extract .xz files and write as csv
os.chdir("./ROAs")
for file in glob.glob("*.csv.xz"):
    with lzma.open(file, "rb") as f:
        with open(file.replace(".xz", ""), "wb") as f2:
            f2.write(f.read())
print("Done extracting all xz files, start merging")

# merge all extracted csvs into one file
mergeROAs()
