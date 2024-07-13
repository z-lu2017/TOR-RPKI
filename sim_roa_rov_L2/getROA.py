import requests
import pandas as pd
import glob

def getROA():
    BASE_URL = "https://ftp.ripe.net/rpki"
    REGIONS = ["afrinic.tal", "apnic.tal", "arin.tal", "lacnic.tal", "ripencc.tal"]
    #MONTHS = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"]
    MONTHS = ["01", "02", "03", "04", "05"]
    #YEARS = ["2021", "2022"]
    YEARS = ["2023"]

    DAYS1 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31']
    DAYS2 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30']
    DAYS3 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28']
    DAYS4 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29']

    for y in YEARS:
        for m in MONTHS:
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
                    with open("/home/ubuntu/TOR-RPKI/TOR-RPKI_Siyang/ROAs" + "/" + r + "-" + y + "-" + m + "-" + d + ".csv.xz", "wb") as f:
                        f.write(resp.content)


def mergeROAs():
    REGIONS = ["afrinic.tal", "apnic.tal", "arin.tal", "lacnic.tal", "ripencc.tal"]
    #MONTHS = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"]
    MONTHS = ["01", "02", "03", "04", "05"]
    #YEARS = ["2021", "2022"]
    YEARS = ["2023"]

    DAYS1 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31']
    DAYS2 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30']
    DAYS3 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28']
    DAYS4 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29']

    for y in YEARS:
        for m in MONTHS:
            if m == "01" or m == "03" or m =="05" or m=="07" or m=="08" or m =="10" or m=="12":
                days = DAYS1
            elif m == "02" and int(y) % 4 == 0:
                days = DAYS4
            elif m == "02" and int(y) % 4 != 0:
                days = DAYS3
            else:
                days = DAYS2

            for d in days:
                joined_list = glob.glob("/home/ubuntu/TOR-RPKI/TOR-RPKI_Siyang/ROAs/*" + y + "-" + m + "-" + d + ".csv")
                df = pd.concat(map(pd.read_csv, joined_list), ignore_index=True)
                df = df[['ASN', 'IP Prefix', 'Max Length']]
                df.to_csv("/home/ubuntu/TOR-RPKI/TOR-RPKI_Siyang/mergedROAs/" +  y + m + d + ".csv", encoding='utf-8', index=False)



#getROA()
mergeROAs()
