import json
import requests
import csv
import time
api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
with open('mdf_files.txt') as mdf:
  for line in mdf:
    params = dict(apikey='221ac507378b186a38cd2eeee0a2404c767f57dd30eba35e3eed206d188f718e', resource=line)
    response = requests.get(api_url, params=params)
    data_file = open('data_file1.csv', 'a')
    if response.status_code == 200:
       result=response.json()
  #ida=json.dumps(result,sort_keys='False',indent=4)
       print(line)
       print(response.status_code)
       if len(result.keys()) > 3:
       
  
# create the csv writer object
         csv_writer = csv.writer(data_file)
         header = result.keys()
         csv_writer.writerow(header)
         csv_writer.writerow(result.values())
         data_file.close()
       #time.sleep(60)
       
       else:
         print('not found',line)


  

        
        
 
    
 
