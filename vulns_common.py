#!/usr/bin/python
from lxml import etree
import xml.dom.pulldom as pulldom
import glob
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
import numpy as np
import pandas as pd
from sklearn.utils import shuffle
import json

def download_cwe_csv(force = False):
    import os.path
    if os.path.isfile('data/1000.csv') and not force:
        return
    import urllib.request
    url = 'https://cwe.mitre.org/data/csv/1000.csv.zip'  
    urllib.request.urlretrieve(url, 'data/1000.csv.zip')

    import zipfile
    zip_ref = zipfile.ZipFile('data/1000.csv.zip', 'r')
    zip_ref.extractall('data/')
    zip_ref.close()

def download_nvd_vulns_json(force = False):
    import os.path
    if os.path.isfile('data/nvdcve-1.0-1-modified.json') and not force:
        return
    import urllib.request
    url = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz'  
    urllib.request.urlretrieve(url, 'data/nvdcve-1.0-modified.json.gz')
    url = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz'  
    urllib.request.urlretrieve(url, 'data/nvdcve-1.0-recent.json.gz')
    url = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2019.json.gz'  
    urllib.request.urlretrieve(url, 'data/nvdcve-1.0-2019.json.gz')
    url = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.gz'  
    urllib.request.urlretrieve(url, 'data/nvdcve-1.0-2018.json.gz')

    import gzip
    import shutil
    with gzip.open('data/nvdcve-1.0-modified.json.gz','rb') as fileread:
        with open('data/nvdcve-1.0-1-modified.json','wb') as filewrite:
            shutil.copyfileobj(fileread, filewrite)
    with gzip.open('data/nvdcve-1.0-recent.json.gz','rb') as fileread:
        with open('data/nvdcve-1.0-1-recent.json','wb') as filewrite:
            shutil.copyfileobj(fileread, filewrite)
    with gzip.open('data/nvdcve-1.0-2019.json.gz','rb') as fileread:
        with open('data/nvdcve-1.0-2019.json','wb') as filewrite:
            shutil.copyfileobj(fileread, filewrite)
    with gzip.open('data/nvdcve-1.0-2018.json.gz','rb') as fileread:
        with open('data/nvdcve-1.0-2018.json','wb') as filewrite:
            shutil.copyfileobj(fileread, filewrite)

def iterate_cpe_nodes(nodes):
    products = []
    for n in nodes:
        try:
            cpe = n['cpe_match'][0]['cpe23Uri']
            parts = cpe.split(':')
            products.append(parts[3])
            products.append(parts[4])
        except:
            cpe = ''
    return products

def load_nvd_vulns_json(file_name):
    cves = list()
    nvdfiles = glob.iglob(file_name)

    for f in nvdfiles:
        file = open(f,'r')
        json_data = json.loads(file.read())

        for entry in json_data['CVE_Items']:
            cve_id = entry['cve']['CVE_data_meta']['ID']
            description = entry['cve']['description']['description_data'][0]['value']
            try:
                cwe = entry['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
            except IndexError:
                cwe = ''
            try:
                cvss2_vector = entry['impact']['baseMetricV2']['cvssV2']['vectorString']
            except:
                cvss2_vector = ''
            try:
                cvss2_score = entry['impact']['baseMetricV2']['cvssV2']['baseScore']
            except:
                cvss2_score = 0.0
            try:
                cvss3_vector = entry['impact']['baseMetricV3']['cvssV3']['vectorString']
            except:
                cvss3_vector = ''
            try:
                cvss3_score = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
            except:
                cvss3_score = 0.0
            cpe = iterate_cpe_nodes(entry['configurations']['nodes'])
            cves.append([cve_id, description, cwe, cvss2_vector, cvss2_score, cvss3_vector, cvss3_score, cpe])

    return cves

import re

def compile_cpe_names(data):
    cpe_words = []
    
    for d in data:
        words = d[7]
        for w in words:
            if re.fullmatch(r'\b\w+\b', w) and w not in cpe_words:#r'\b\w*[a-zA-Z]{3,}\w*\b'
                cpe_words.append(w)
    return cpe_words

import nltk

def remove_cpe_names(raw_document, cpe_names):
    tokens = nltk.word_tokenize(raw_document)
    for token in tokens:
        if token in cpe_names:
            raw_document = re.sub(r'\bin\b', token, raw_document)

    return raw_document

def print_vulns_metrics(ground_truth, actual):
    print(classification_report(y_true=ground_truth, y_pred=actual))
    tn, fp, fn, tp = confusion_matrix(y_true=ground_truth, y_pred=actual).ravel()
    print('TN={}, FP={}, FN={}, TP={}'.format(tn, fp, fn, tp))

def preprocess_csv_data(reports):
    reports = reports.rename(str.lower, axis='columns')
    if not 'report' in reports.columns:#these steps not required on the Chromium dataset
        reports['report'] = reports['summary   '] + reports['description   ']
#        no_improvements = reports['type'] == "Bug"
        reports = reports[:][['report', 'security']]
    reports = reports.replace([np.inf, -np.inf], np.nan).dropna(subset=['security'], how="all")
    reports['security'] = reports['security'].values.astype(bool)
    reports['report'] = reports['report'].values.astype(str)

    return reports

def print_classified_dataset(file_name, pipe):
    reports = pd.read_csv(file_name)
    reports = shuffle(reports, n_samples=1000)
    print('Test on ' + file_name + '. Rows: ' + str(len(reports.index)))
    reports = preprocess_csv_data(reports)

    predicted = pipe.predict(reports['report'])
    if type(predicted[0]) == bool:
        reports['predicted'] = predicted 
    else:
        reports['predicted'] = (predicted == 1)
       
    print_vulns_metrics(reports['security'], reports['predicted'])

def get_mixed_dataset(data, number):
    num = int(number/5)
    
    reports = pd.read_csv('data/Ambari.csv')
    reports = preprocess_csv_data(reports)
    s1 = reports.loc[(reports['security']==0)]
    s1 = s1.sample(n=num)

    reports = pd.read_csv('data/Camel.csv')
    reports = preprocess_csv_data(reports)
    s2 = reports.loc[(reports['security']==0)]
    s2 = s2.sample(n=num)

    reports = pd.read_csv('data/Wicket.csv')
    reports = preprocess_csv_data(reports)
    s3 = reports.loc[(reports['security']==0)]
    s3 = s3.sample(n=num)

    reports = pd.read_csv('data/Chromium.csv')
    reports = preprocess_csv_data(reports)
    s4 = reports.loc[(reports['security']==0)]
    s4 = s4.sample(n=num)

    reports = pd.read_csv('data/Derby.csv')
    reports = preprocess_csv_data(reports)
    s5 = reports.loc[(reports['security']==0)]
    s5 = s5.sample(n=num)

    frames = [s1, s2, s3, s4, s5]
    non_sec_issues = pd.concat(frames, sort=False)
    non_sec_issues = non_sec_issues.drop(['date','id'],axis=1)
    non_sec_issues['security'] = -1

    sec_issues = pd.DataFrame(data)
    sec_issues['security'] = 1
    sec_issues.columns = ['report', 'security']

    frames = [non_sec_issues, sec_issues]
    mixed = pd.concat(frames, sort=False)

    return mixed.sample(frac=1)

class CweFinder():
    def __init__(self):
        self.cwes = pd.read_csv('data/1000.csv', index_col=False)
        self.cwes['CWE-ID'] = self.cwes['CWE-ID'].values.astype(str)

    def find_parent_cwe(self, cwe_id):
        cwe = self.cwes[self.cwes['CWE-ID'] == cwe_id]
        if(cwe.empty):
            return ''
        cwe = cwe.iloc[0]['Related Weaknesses']
        if type(cwe) != str:
            return ''
        s = cwe.find('ChildOf:CWE ID:')
        e = cwe.find(':', s+15)
        if s == -1 or e == -1:
            return ''
        return cwe[s+15:e]

    def find_root_cwe(self, cwe_id):
        parent = self.find_parent_cwe(cwe_id)
        if len(parent) <= 0:
            return cwe_id
        else:
            return self.find_root_cwe(parent)
