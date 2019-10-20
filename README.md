# Vulnerability Prediction Experiments

These Jupyter Notebook experiments are about finding vulnerable-like descriptions from any text and classifying vulnerability severities and weakness types. Vulnerability severities are measured using Common Vulnerability Scoring System. Common Weakness Enumeration is a hierarchical list of weakness types that each vulnerability can be classified to. The scoring and weakness type information for known vulnerabilities are available on National Vulnerability Database. The Scikit-learn library’s interfaces were used extensively to implement text preprocessing, machine learning classification, and experiment validation. Experiments include stemming, lemmatization, and numerous text vectorization options and algorithms provided by the library.

### Contents

- CWE Test.ipynb: Common Weakness Enumeration classification 
- CVSS Test.ipynb: Common Vulnerability Scoring System classification (CVSS2 and CVSS3)
- Keyword Test.ipynb: Keyword based Classifier experiments
- OneClass Test.ipynb: One-class Classifiers experiments
- vulns_common.py: Common functions which are used in .ipynb files

### Prerequisities

Install Anaconda for Python 3.X
- https://www.anaconda.com/distribution/#download-section

Install cvsslib
- In Anaconda Prompt: pip install cvsslib

