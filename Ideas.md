"""
Function 1 - taking in a Link/Url and comparing it to potential malicicous links

What we want to catch:
- Brand impersonation (phising scheames)
- Known malicious links

methods:
- get data using external APIs and compare it to the data to the link to detect malicious activity 
  - Virus Total API
  - urlscan.io API
  - Google Safe Browsing API `
  - incorperate more than the current API based on the chance some APIs cannot parse some sites due to anti botting, solution is use multiple tools
    incorperate a final score of the likelyhood a site is malicious 
"""
