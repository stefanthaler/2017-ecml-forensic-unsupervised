import argparse     # parse command line ptions
import wget
import os
import gzip
import shutil

from library.all_experiments import * # experiments are defined here

def lib_name(exp_nr):
    if exp_nr in EXPERIMENT_LIB_MAPPING:
        return "data_generation.%s"%EXPERIMENT_LIB_MAPPING[exp_nr]
    else:
        return "data_generation.%s"%ALL_EXPERIMENTS[exp_nr]



# parse arguments
parser = argparse.ArgumentParser(description='Prepares the dataset for the experiment with a given number. Check library/all_experiments.py for more information')
parser.add_argument('-e', '--experiment_nr', type=int, default=11, help='The experiment number as defined in library/all_experiments.py') #spirit2.log
args = parser.parse_args()


experiment_nr = args.experiment_nr
if experiment_nr not in[11, 13]:
    print("Experiment number not supported - %i, only 11 and 13 are supported."%experiment_nr)
    import sys
    sys.exit(0)

EXPERIMENT_ID = ALL_EXPERIMENTS[experiment_nr] # choose data - it will be automatically generated
print("Running experiment: %s"%EXPERIMENT_ID)

# Download file
print("Downloading file...")
zip_fn = os.path.join("data_raw", DOWNLOAD_FN[experiment_nr] )
if os.path.exists(zip_fn):
    print("File %s already exists, skip download"%zip_fn)
else:
    zip_fn = wget.download(url=DOWNLOAD_URLS[experiment_nr],out ="data_raw" )
#zip_fn = "data_raw/bgl2.gz"
print("File downloaded to... %s"%zip_fn)


print("Extracting file...")
log_fn = zip_fn.replace("gz","log")
if os.path.exists(log_fn):
    print("Log %s already exists, skip extracting"%log_fn)
else:
    with gzip.open(zip_fn, 'rb') as f_in:
        with open(log_fn, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

#log_fn = "data_raw/spirit.log"

print("Stratifying dataset...")
os.system("python data/create_stratified_log.py -if %s -ns %i"%(log_fn,NUM_STRATA[experiment_nr]))

print("Preparing dataset...")

log_fn_0 = log_fn.replace(".log","_00.log") # pick first strata
command = "python data_generation/%s.py -if %s -c 1"%(EXPERIMENT_LIB_MAPPING[experiment_nr], log_fn_0)
print(command)
os.system(command)

log_fn_0_clean = log_fn_0+"_clean"
shutil.copy(log_fn_0_clean, os.path.join("data", EXPERIMENT_ID+".log" ))


print("%s prepared. You should now be able to run the experiment from the jupyter notebook "%EXPERIMENT_ID)
