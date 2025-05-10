"""
Python script to check if domain name is alive for future analysis
"""
__author__ = "Alisher Mazhirinov"

import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
import os
import argparse
from usefull_imports import stop_words
import nltk
from nltk.corpus import stopwords

# uncomment the before running the script for the first time
#nltk.download('stopwords')

# Loading stop words from NLTK
nltk_stopwords = set(stopwords.words('english'))

parser = argparse.ArgumentParser(description="Feature Extraction program, chooose parameters to extract features. Script automatically finds the path to a file. Example: python3 featureExtraction.py -p -e")

parser.add_argument("-p", "--phishing", action="store_true", help="Flag for feature extraction of phishing file")
parser.add_argument("-m", "--malware", action="store_true", help="Flag for feature extraction of malware file")
parser.add_argument("-b", "--benign", action="store_true", help="Flag for feature extraction of benign file")

parser.add_argument("-e", "--english", action="store_true", help="Flag for feature extraction of english webpages")
parser.add_argument("-g", "--german", action="store_true", help="Flag for feature extraction of german webpages")
parser.add_argument("-f", "--french", action="store_true", help="Flag for feature extraction of french webpages")
parser.add_argument("-s", "--spanish", action="store_true", help="Flag for feature extraction of spanish webpages")
parser.add_argument("-r", "--russian", action="store_true", help="Flag for feature extraction of russian webpages")
parser.add_argument("-c", "--czech", action="store_true", help="Flag for feature extraction of czech webpages")

args = parser.parse_args()
OUTPUT_FILE = "5_extracted_features/new_row/"



# A class for extracting TF-IDF-based features from the content of a domain name.
# It reads text data from a language- and type-specific CSV file, cleans it,
# filters out stopwords, calculates TF-IDF values, and saves the extracted features to a CSV file.
class FeatureExtraction:
    def __init__(self, domain_type, language, stopwords_set, label):
        self.domain_type = domain_type
        self.language = language
        self.stopwords_set = stopwords_set
        self.label = label
        self.file = "4_divided_by_languages/" + domain_type + "/" + domain_type + "_" + language + ".csv"
    
    def is_stopword(self, word):
        return word.lower() in self.stopwords_set
    
    def clean_text_advanced(self, text):
        text = re.sub(r"[^a-zA-Zа-яА-ЯёЁčďěňřšťůžýáíéóúüöäßñç ]", "", text)  # Remove special characters and numbers
        text = re.sub(r"\s+", " ", text).strip()
        words = text.split()  # Break the string into words
        filtered_words = [
            word for word in words 
            if not self.is_stopword(word) and word.lower() not in nltk_stopwords
        ] # Eliminate stop words
        return " ".join(filtered_words)
    
    def extract_features(self):
        print(f"Extraction of {self.language} {self.domain_type} features")
        df = pd.read_csv(self.file)
        cleaned_text_list = [self.clean_text_advanced(text) for text in df['text'].tolist()]
        domains = df['domain_name'].tolist()
        mal_tags = df['malicious_tags'].tolist()
        tags = df['all_tags'].tolist()
        words_c = df['text'].tolist()
        all_data = []
        if self.language == "czech":
            lang = "cs"
        elif self.language == "spanish":
            lang = "es"
        elif self.language == "german":
            lang = "de"
        else:
            lang = self.language[:2]

        max_feat = 30
        
        vectorizer = TfidfVectorizer(max_features=max_feat)
        tfidf_matrix = vectorizer.fit_transform(cleaned_text_list)
        words = vectorizer.get_feature_names_out()
        tfidf_array = tfidf_matrix.toarray()
        
        for doc_idx, doc_tfidf in enumerate(tfidf_array):
            # Create an index-value pair and filter out zeros
            word_tfidf_pairs = [(words[i], doc_tfidf[i]) for i in range(len(doc_tfidf)) if doc_tfidf[i] > 0]
            
            # Sort pairs by TF-IDF value in descending order
            sorted_word_tfidf_pairs = sorted(word_tfidf_pairs, key=lambda x: x[1], reverse=True)
            domain_name = domains[doc_idx]
            malicious_tags = mal_tags[doc_idx]
            domain_length = len(domains[doc_idx])
            word_count = words_c[doc_idx].count(" ") + 1
            all_tags = tags[doc_idx]
            
            # Display top words with the highest TF-IDF
            for word, tfidf_value in sorted_word_tfidf_pairs:
                    all_data.append({
                        'domain_name': domain_name,
                        'label': self.label,
                        'language': lang, 
                        'malicious_tags': malicious_tags,
                        'all_tags': all_tags,
                        'domain_length': domain_length,
                        'words_count': word_count,
                        'index': tfidf_value,
                        'word': word
                    })
                  
        result = pd.DataFrame(all_data)
        final_output = OUTPUT_FILE + self.domain_type + "/" + "extracted_" + self.domain_type + "_" + self.language + ".csv"
        if os.path.exists(final_output):
            print("File already exists, trying to add new data...")
            existing_df = pd.read_csv(final_output)
            new_data = result.loc[~result['domain_name'].isin(existing_df['domain_name'])]
            if not new_data.empty:
                # Append new data to the existing file
                new_data.to_csv(final_output, mode='a', index=False, header=False)
        else:
            # If file does not exist, save all the data
            result.to_csv(final_output, mode='w', index=False, header=True)
            
        
        
        

if args.phishing:
    if args.english:
        phishing = FeatureExtraction("phishing", "english", stop_words.english_stopwords, 1)
    elif args.german:
        phishing = FeatureExtraction("phishing", "german", stop_words.german_stopwords, 1)
    elif args.french:
        phishing = FeatureExtraction("phishing", "french", stop_words.french_stopwords, 1)
    elif args.spanish:
        phishing = FeatureExtraction("phishing", "spanish", stop_words.spanish_stopwords, 1)
    elif args.russian:
        phishing = FeatureExtraction("phishing", "russian", stop_words.russian_stopwords, 1)
    else:
        print("Wrong language")
        exit()
    print(phishing.domain_type)
    print(phishing.language)
    phishing.extract_features()
elif args.malware:
    if args.english:
        malware = FeatureExtraction("malware", "english", stop_words.english_stopwords, 1)
    elif args.german:
        malware = FeatureExtraction("malware", "german", stop_words.german_stopwords, 1)
    elif args.french:
        malware = FeatureExtraction("malware", "french", stop_words.french_stopwords, 1)
    elif args.spanish:
        malware = FeatureExtraction("malware", "spanish", stop_words.spanish_stopwords, 1)
    elif args.russian:
        malware = FeatureExtraction("malware", "russian", stop_words.russian_stopwords, 1)
    elif args.czech:
        malware = FeatureExtraction("malware", "czech", stop_words.czech_stopwords, 1)
    else:
        print("Wrong language")
        exit()
    print(malware.domain_type)
    print(malware.language)
    malware.extract_features()
elif args.benign:
    if args.english:
        benign = FeatureExtraction("benign", "english", stop_words.english_stopwords, 0)
    elif args.german:
        benign = FeatureExtraction("benign", "german", stop_words.german_stopwords, 0)
    elif args.french:
        benign = FeatureExtraction("benign", "french", stop_words.french_stopwords, 0)
    elif args.spanish:
        benign = FeatureExtraction("benign", "spanish", stop_words.spanish_stopwords, 0)
    elif args.russian:
        benign = FeatureExtraction("benign", "russian", stop_words.russian_stopwords, 0)
    elif args.czech:
        benign = FeatureExtraction("benign", "czech", stop_words.czech_stopwords, 0)
    else:
        print("Wrong language")
        exit()
    print(benign.domain_type)
    print(benign.language)
    benign.extract_features()
else:
    print("Wrong type of file or no parameters given")
    exit()

