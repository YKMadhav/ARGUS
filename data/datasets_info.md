# Dataset Information

## Overview

The ARGUS machine learning models were developed and evaluated using publicly available cybersecurity datasets.

These datasets provide examples of both benign and malicious network traffic, enabling the training and validation of anomaly detection models used within ARGUS.

---

## Datasets Used

### CICIDS2017

**Status:** Not included in this repository due to dataset size limitations.

The CICIDS2017 dataset contains realistic network traffic and a wide range of modern cyberattack scenarios.

**Attack Categories Include:**

* DDoS Attacks
* Port Scanning
* Brute Force Attacks
* Botnet Activity
* Web-Based Attacks

---

### NSL-KDD

The NSL-KDD dataset is an improved version of the KDD Cup 1999 dataset and is widely used in intrusion detection research.

**Advantages:**

* Reduced redundancy
* Improved dataset balance
* Benchmark dataset for IDS evaluation

---

### KDDTest

The KDDTest dataset is used to evaluate model performance against previously unseen network traffic and attack patterns.

---

## Purpose

These datasets are used to:

* Train anomaly detection models
* Validate threat detection performance
* Evaluate classification accuracy
* Benchmark model effectiveness

---

## Machine Learning Models

The processed datasets are used to train and validate:

* Isolation Forest
* Future supervised classifiers
* Future ensemble detection models

---

## Disclaimer

The datasets included in this repository are used solely for educational, research, and demonstration purposes within the ARGUS project.

All dataset credits belong to their respective creators and maintainers.
