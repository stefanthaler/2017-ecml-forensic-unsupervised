import argparse     # parse command line ptions
from os.path import join as path_join
import importlib
import os

# parse arguments
parser = argparse.ArgumentParser(description='Adds line numbers to dataset')
parser.add_argument('-en', '--experiment_name', type=str, default="unix_log", help='')
parser.add_argument('-ln', '--library_name', type=str, default=None, help='')
args = parser.parse_args()
experiment_name = args.experiment_name
if args.library_name:
    library_name = args.library_name
else:
    library_name = experiment_name

# pepare filenames
log_file_name = path_join("data", "%s.log"%experiment_name )
experiment_lib = importlib.import_module("data_generation.%s"%library_name)
signature_file =  path_join("data", "%s.ids"%experiment_name  )

if os.path.exists(signature_file) and os.stat(signature_file).st_size > 0 :
    print("Signature file '%s' already exists"%signature_file)
else:
    print("Loading true cluster labels..")
    log_lines  = list(open(log_file_name, 'r'))
    one_percent = len(log_lines)/100

    zero_sigs = []
    sf = open(signature_file,"w")

    for i, logline in enumerate(log_lines):
        if i%one_percent==0:
            print("%.3d percent, processed line %i"%(i/one_percent, i))
        signature_id = experiment_lib.extract_pattern_id(logline)
        sf.write("%s\n"%signature_id)
        if signature_id==0:
            zero_sigs.append(logline)
    sf.close()

    print("Unassigned Signatures:")
    print(zero_sigs)
    assert len(zero_sigs)==0, "All log lines have to have a signature"
