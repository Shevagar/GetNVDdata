# GetNVDdata
This is an application to download NVD data using REST APIs. 
The purpose here is to download CVE related data and then analyse it further.
Currently the Application takes CVE list as an input and generates output along with the Affected Library,Version, CVE Description 
Its basic code that was required for my analysis.
Please feel free to ask for extensions and feature add.

#How to execute
Add cves in the sampledata.csv file
Execute main.py
You get the details of eachCVE in the form of individual json file and a new csv file containg specific information

#issue
Its a very basic code to download data 
The code might crash for the CVEs that are rejected.
