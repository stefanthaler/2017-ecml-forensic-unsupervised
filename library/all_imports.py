import builtins as g
import tensorflow as tf
print ("Using TensorFlow version %s"%tf.__version__)
import numpy as np

import nltk
import itertools

import os
from os import listdir
from os.path import join as join_path

import importlib # for dynamically importing experiment lib

import sys
import matplotlib
matplotlib.use('Agg') # Must be before importing matplotlib.pyplot or pylab!
import matplotlib.pyplot as plt

from IPython.display import Image # for displaying inline images

import multiprocessing
from multiprocessing import Process, Queue
from random import shuffle
import re

from collections import namedtuple
from collections import OrderedDict

import json # for saving variables to json
import csv # for writing csv files
import time # for timing operations
import datetime
now = datetime.datetime.now()
now_str = now.strftime("%Y%m%d-%H-%M") # will be used for naming experiment output folders

# tensorflow operations used

# dynamic rnn decoder
from tensorflow.contrib.seq2seq.python.ops.seq2seq import dynamic_rnn_decoder
from tensorflow.contrib.seq2seq.python.ops.attention_decoder_fn import attention_decoder_fn_train,attention_decoder_fn_inference
from tensorflow.contrib.seq2seq.python.ops.decoder_fn import simple_decoder_fn_train
from tensorflow.contrib.seq2seq.python.ops.attention_decoder_fn import prepare_attention
from tensorflow.contrib import rnn as contrib_rnn

# for visualizing the hierarchical clustering dendrogram
import scipy
from scipy.cluster import hierarchy
import matplotlib.pyplot as plt
from scipy.stats import pearsonr as pearson_correlation

# for calculating shillouette score and other cluster metrics
import sklearn
from sklearn import metrics # for calculating v-measure, homogenity, completeness
from sklearn.cluster import AffinityPropagation
from sklearn.datasets.samples_generator import make_blobs
