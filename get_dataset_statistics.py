"""
    Gets dataset statistics
"""

import argparse     # parse command line ptions
from os.path import join as path_join
import importlib
import os
from library.helpers import print_progress, execute_command as ex, multiprocess_file
#import re
from time import time as now
import numpy as np

# parse arguments
parser = argparse.ArgumentParser(description='Adds line numbers to dataset')
parser.add_argument('-en', '--experiment_name', type=str, default="spirit2_00", help='')
parser.add_argument('-ln', '--library_name', type=str, default=None, help='')
parser.add_argument('-np', '--num_processes', type=int, default= 8, help='')
args = parser.parse_args()
experiment_name = args.experiment_name
if args.library_name:
    library_name = args.library_name
else:
    library_name = experiment_name
num_processes = args.num_processes

# pepare filenames
log_file_name = path_join("data", "%s.log"%experiment_name )
experiment_lib = importlib.import_module("data_generation.%s"%library_name)
print("Parsing experiment: %s "%log_file_name)
print("Signature Library: %s"%library_name)

# resultfile
sanitycheckfile = open("data/%s_statistics.txt"%experiment_name,"w")

# get number of lines
line_numers = int(ex("wc -l %s"%log_file_name).split()[0])

# run through all lines
s = now()
def extract_pattern_from_line(line_q, result_q):
    # get item blocking
    new_line = line_q.get(timeout=5)
    # do something
    result =  experiment_lib.extract_pattern_id(new_line)
    # get back result
    result_q.put(result)

if __name__ == '__main__':
    counts = [0]*(len(experiment_lib.KNOWN_LOGLINE_PATTERN)+1)

    result_q, _,_,_ = multiprocess_file(log_file_name,extract_pattern_from_line)

    signatures_used = set([])

    for i in xrange(line_numers):
        if i%500==0:
            print_progress(i, line_numers, " counting dataset statistics")
        pid = result_q.get()
        counts[pid]+=1
        signatures_used.add(pid)

    print("Min: %i"%min(counts))
    print("Max: %i"%max(counts))
    print("Lower Quartile %.2f"%np.percentile(counts, 25))
    print("Median: %.2f"%np.median(counts))
    print("Upper Quartile %.2f"%np.percentile(counts, 75))
    print("Std: %0.2f"%np.std(counts))
    with open("data/%s_statistics.txt"%experiment_name, "w") as f:
        f.write("Min: %i\n"%min(counts))
        f.write("Max: %i\n"%max(counts))
        f.write("Lower Quartile %.2f\n"%np.percentile(counts, 25))
        f.write("Median: %.2f\n"%np.median(counts))
        f.write("Upper Quartile %.2f\n"%np.percentile(counts, 75))
        f.write("Mean: %i\n"%np.mean(counts))
        f.write("Std: %0.2f\n"%np.std(counts))
        f.write("Lines: %i\n"%line_numers)
        f.write("Signatures used: %i"%len(signatures_used))

    with open("data/%s_counts.json"%experiment_name,"w") as f:
        json_coutns_str = json.dumps(counts)
        f.write(json_coutns_str)
print("Done in %s seconds"%(now()-s))
