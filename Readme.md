# TF-IDF classification models

## Author
Alisher Mazhirinov, VUT FIT 2025

## Pipeline Overview

### 1. `findAliveDomainName`
- Checks if a web page is alive and accessible.
- If the page is reachable, its domain name is stored for further processing.

### 2. `scrapeWebPage`
- Scrapes the content of the web page.
- Extracts:
  - Raw text
  - Detected language
  - Total number of HTML tags
  - Number of suspicious or unusual tags

### 3. `divideByLanguage.ipynb`
- Splits the dataset by detected language for more efficient TF-IDF computation.

### 4. `featureExtraction`
- Computes TF-IDF features for english dataset.
- For each domain name prints top 30 words with TF-IDF indexes.

### 5. `divideFeature`
- Using the TF-IDF indexes and top 30 words, counts number of occurences of these words in the text of a domain name web page.
- Prepares feature vectors for the model.

### 6. Training and testing models
- Trains and evaluates machine learning models using the extracted features.
- Includes files:
  - malware_tfidf_lgbm_train.ipynb
  - phishing_tfidf_lgbm_train.ipynb
  - malwareDecTreeRndForest.ipynb
  - phishingDecTreeRndForest.ipynb


### 7. Pipeline Flow

- findAliveDomainName -> scrapeWebPage ->  divideByLanguage -> featureExtraction -> divideFeatures -> Classfication Models