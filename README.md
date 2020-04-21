# Unsupervised Signature Extraction for Forensic Logs

This repository contains the experiments of the paper "Unsupervised Signature Extraction from forensic logs."


# Perparation:
## Requirements
* Linux: python3.5, python3-pip, python3-venv

## Setup
* python3 -m venv .env
* . .env/bin/activate.fish / source .env/bin/activate
* pip install -r requirements.txt

# Obtain and Prepare data
* python prepare_dataset.py -e 11  (for BGL)
* python prepare_dataset.py -e 13  (for Spirit2)

# Run the experiments
* jupyter notebook
* set your experiment_id in Section "Hyperparameter":
* choose experiment_nr = 6 # 6 (unix forensic), 11 (bgl), 13 (spirit2)
* click "Clear and run all"

# Datasets (https://www.usenix.org/cfdr-data)
* BlueGene/L: http://0b4af6cdc2f0c5998459-c0245c5c937c5dedcca3f1764ecc9b2f.r43.cf2.rackcdn.com/hpc4/bgl2.gz
* Spirit2: http://0b4af6cdc2f0c5998459-c0245c5c937c5dedcca3f1764ecc9b2f.r43.cf2.rackcdn.com/hpc4/spirit2.gz


# Work used in this paper:
## IPLoM Implentation:
Paper of IPLoM:
* Title: 2012, Makanju et al.,  "A lightweight algorithm for message type extraction in system application logs"
* DOI: http://dx.doi.org/10.1109/TKDE.2011.138

## Paper that provided IPLoM sourcecode:
* Title: 2014, He et al. , "An Evaluation Study on Log Parsing and Its Use in Log Mining"
* Link: http://jiemingzhu.github.io/pub/pjhe_dsn2016.pdf
* SourceCode: https://github.com/cuhk-cse/logparser/commit/d3fe123235899a2cf2d454434a3eb1a1222f03bd

## LogCluster implementation
* Title: 2015, Vaarandi et al. - LogCluster - A Data Clustering and Pattern Mining Algorithm for Event Logs
* SourceCode: https://github.com/ristov/logcluster/commit/eadbf25df94257dc3cf72bb79e672d257bbce616
