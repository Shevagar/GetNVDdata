import requests
import json
import csv
import pandas as pd

def getversion(match):
 version=''
 if match.get('versionEndIncluding') is not None:
    print("Affected version end:1", match['versionEndIncluding'])
    version+=' versionEndIncluding:'+match['versionEndIncluding']
 else:
    print('versionEndIncluding not found')
 if match.get('versionStartIncluding') is not None:
    print("Affected version end:1", match['versionStartIncluding'])
    version+=' versionStartIncluding:'+match['versionStartIncluding']
 else:
    print('versionStartIncluding not found')
 if match.get('versionStartExcluding') is not None:
    print("Affected version excluding:", match['versionStartExcluding'])
    version+=' versionStartExcluding:'+match['versionStartExcluding']
 else:
    print('versionStartExcluding not found')
 if match.get('versionEndExcluding') is not None:
    print("Affected version end excluding:", match['versionEndExcluding'])
    version+=' versionEndExcluding:'+match['versionEndExcluding']
 else:
    print('versionEndExcluding not found')
 return version
 
def downloadcvedata(api_key, cve_list):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

    headers = {"api_key": api_key}

    with open('newcve.csv', mode='w', newline='') as filewrite:
        fieldnames = {'cve_id', 'description', 'library', 'version'}
        writer = csv.DictWriter(filewrite, fieldnames=fieldnames)
        writer.writeheader()
        for cve_id in cve_list:
            url = base_url + cve_id
            print(url)
            response = requests.get(url, headers=headers)
            # response2= requests.get(url1, headers=headers)
            if response.status_code == 200:
                cve_data = response.json()
                print("Downloaded CVE data for {cve_id}")
                filename = 'cve_data' + cve_id
                # Process cve_data as needed
                with open(filename, 'w') as json_file:
                    json.dump(cve_data, json_file)
                    # print(json.dumps(cve_data, indent=2))
                    # print(json.dumps(cve_data, indent=2))
                    description = cve_data['vulnerabilities'][0]['cve']['descriptions'][0]['value']
                    print(cve_data['vulnerabilities'][0]['cve']['descriptions'][0]['value'])
                    if cve_data['vulnerabilities'][0]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0][
                        'criteria'] != "":
                        lib = cve_data['vulnerabilities'][0]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0][
                            'criteria']
                        print(cve_data['vulnerabilities'][0]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0][
                                  'criteria'])
                    else:
                        lib = 'NA'

                    if cve_data['vulnerabilities'][0]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0] != "":
                        version = getversion(cve_data['vulnerabilities'][0]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0])
                        print(version)
                    else:
                        version = 'NA'
                    writer.writerow({'cve_id': cve_id, 'description': description, 'library': lib, 'version': version})
                # ['versionStartIncluding'])
                # print(cve_data['vulnerabilities'][0]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0]['versionEndExcluding'])
            else:
                print("Failed to download CVE data for {cve_id}. Status code: {response.status_code}")
            #filewrite.close()



