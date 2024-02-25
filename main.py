import downloadcvedata
import requests
import json
import csv
import pandas as pd

# Replace 'XXXXX' with your actual NVD API key

api_key = "XXXXXX"

# Replace the example CVE IDs with your own list

cve_list = []

with open('sample.csv', newline='') as csvfile:
   reader = csv.DictReader(csvfile)
   for col in reader:
      cve_list.append(col['cveid'])
   csvfile.close()
   print(cve_list)
   downloadcvedata.downloadcvedata(api_key, cve_list)


input_file_path = 'sample.csv'


