import requests
import subprocess
import shlex
import os

a_string = ""
escaped = a_string.translate(str.maketrans({"-":  r"\-",
                                          "]":  r"\]",
                                          "\\": r"\\",
                                          "^":  r"\^",
                                          "$":  r"\$",
                                          "*":  r"\*",
                                          ".":  r"\."}))

def getRV():
    BASE_URL = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as"
    #MONTHS = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"]
    MONTHS = ["01", "02", "03", "04", "05"]
    #YEARS = ["2021", "2022"]
    YEARS = ["2024"]
    days1 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31']
    days2 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30']
    days3 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28']
    days4 = ['01', '02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29']

    for y in YEARS:
        for m in MONTHS:  
            if int(y) % 4  == 0:
                quadrennial = True
            else:
                quadrennial = False

            if quadrennial == True and m == "02":
                days = days4
            elif quadrennial == False and m == "02":
                days = days3
            elif m == "01" or m == "03" or m =="05" or m=="07" or m=="08" or m =="10" or m=="12":
                days = days1
            elif m == "04" or m=="06" or m=="09" or m=="11":
                days = days2
            
            for d in days:
                url = BASE_URL + "/" + y + "/" + m + "/routeviews-rv2-" + y + m + d + "-1200.pfx2as.gz"
                resp = requests.get(url)
                with open("/home/ubuntu/TOR-RPKI/TOR-RPKI_Siyang/routeviews/"  + "routeviews-rv2-" + y + m + d + "-1200.pfx2as.gz", "wb") as f:
                    f.write(resp.content)


# grab all routeviews for the first of each month
getRV()
# # extract .gz files
# os.chdir("/home/ubuntu/TOR-RPKI/TOR-RPKI_Siyang/routeviews")
# subprocess.run(shlex.split('gzip -d *.pfx2as.gz'))
