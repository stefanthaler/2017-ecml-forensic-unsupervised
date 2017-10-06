"""
    loads a clustering results file and generates the plot for the graph
"""

import argparse     # parse command line ptions
from os.path import join as join_path
import importlib
import os
from library.helpers import print_progress, execute_command as ex, multiprocess_file, pd, load_from_csv
import re as re
#import re
from time import time as now
import numpy as np
from sklearn.decomposition import PCA
import sklearn
from scipy.cluster import hierarchy
from sklearn import metrics # for calculating v-measure, homogenity, completeness
from library.plotting import plot
from IPython.display import Image

# parse arguments
parser = argparse.ArgumentParser(description='Evaluates clustering')
parser.add_argument('-en', '--experiment_name', type=str, default="spirit2", help='')
parser.add_argument('-ln', '--library_name', type=str, default="spirit2_00", help='')
args = parser.parse_args()
experiment_name = args.experiment_name
if args.library_name:
    library_name = args.library_name
else:
    library_name = experiment_name


CLUSTERING_RESULTS_FILE = "results/13_spirit2_00/20170420-16-28-birch-15/clustering_results.csv"
experiment_outdir = "results/13_spirit2_00/20170420-16-28-birch-15/"
run_tag = "rnn-autoencoder"
cluster_alg="birch"

cluster_plot_file = join_path(experiment_outdir, "%s_clustering_homog-compl-vscore.png"%cluster_alg)
cluster_results = np.array(load_from_csv(CLUSTERING_RESULTS_FILE)[1:], dtype="float32")

plot(cluster_results, x_row=0, x_label="Thresholds-%s"%run_tag, x_tick_step=3,
     y_rows=[0,1,2, 4], y_labels=["Homogenity","Completeness", "V-Score", "Adj Mut. Info"],y_markers=["o","o","s","v"],y_colors=["r","g","b","c"],
     cluster_plot_file= cluster_plot_file )
Image(filename=cluster_plot_file)
