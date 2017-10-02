import colorsys # for get_N_HexCol
import os
import json
import csv
import sys
import subprocess
from multiprocessing import Process, Queue
import subprocess # copy text to clipboard
import time

def pd(what, start_time):
    time_in_min = (time.time() - start_time) / 60.0
    time_in_h = time_in_min / 60.0
    print("%s took ~%0.2f min, ~%0.2f h"%(what, time_in_min, time_in_h))

def copy2clip(txt):
    cmd="echo '"+txt.strip()+"'| xsel --clipboard"
    return subprocess.check_call(cmd, shell=True)

# https://stackoverflow.com/questions/4760215/running-shell-command-from-python-and-capturing-the-outputhttps://stackoverflow.com/questions/4760215/running-shell-command-from-python-and-capturing-the-output
def execute_command(command_str):
    command_pieces = command_str.split(" ")
    return subprocess.check_output(command_pieces)

# saves a file to the experiment directory
def save_to_json(data, outfile_name):
    with open(outfile_name, "w") as f:
        f.write( json.dumps( data ) )
    print("Saved to json: %s."%outfile_name)

# dump data array to file
def save_to_csv(data_rows, outfile_name):
    with open(outfile_name, "w") as f:
        cw =  csv.writer(f,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for data_row in data_rows:
            cw.writerow(data_row)
    print("Saved to csv: %s."%outfile_name)

# load data from vocabulary
def load_from_json(infile_name):
    with open(infile_name, "r") as f:
        print("Loaded from json: %s"%infile_name)
        json_str = f.read()
        return json.loads(json_str)

# load data from csv
def load_from_csv(infile_name):
    with open(infile_name, "r") as f:
        read_rows =  csv.reader(f,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        rows = []
        for row in read_rows:
            rows.append(row)
        print("Loaded from csv: %s."%infile_name)
        return rows

def create_if_not_exists(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

def num_lines(file_name):
    return int(execute_command("wc -l %s"%file_name).split()[0])

# get a hex color range for number of parts
def get_N_HexCol(N=5):
    HSV_tuples = [(x*1.0/N, 1, 1) for x in xrange(N)]
    hex_out = []
    for rgb in HSV_tuples:
        rgb = map(lambda x: int(x*255),colorsys.hsv_to_rgb(*rgb))
        hex_out.append("#"+ "".join(map(lambda x: chr(x).encode('hex'),rgb)).upper() )
    return hex_out
"""
def process_one_line(line_q, result_q, ):
    # get item blocking
    new_line = line_q.get(timeout=5)
    # do something
    result =  experiment_lib.extract_pattern_id(new_line)
    # get back result
    result_q.put(result)
"""
def multiprocess_file(file_name, process_one_line,  num_processes=8, max_size=10000):
    # define multithreading
    line_q = Queue(maxsize=max_size)
    result_q = Queue()

    # process for scooping lines to process on input q
    def load_line(line_q, file_name):
        for l in open(file_name, 'r'):
            line_q.put(l)
    # wrapper for processing the line in one loop
    def proccess_one_line_loop(line_q,result_q,pid):
        try:
            while True:
                process_one_line(line_q,result_q)
        except Exception as e:
            print(e)
            print("Shutting down processing thread %i"%pid)

    # define processes
    processes = []
    for pid in xrange(num_processes):
        processes.append(Process(target=proccess_one_line_loop, args=(line_q,result_q,pid)))

    line_load_p = Process(target=load_line, args=(line_q,file_name))

    # start threads
    [p.start() for p in processes]
    line_load_p.start()

    return result_q, line_q, processes, line_load_p





# Print iterations progress
def print_progress (iteration, total, prefix = '', suffix = '', decimals = 2, barLength = 100):
    filledLength    = int(round(barLength * iteration / float(total)))
    percents        = round(100.00 * (iteration / float(total)), decimals)
    bar             = '#' * filledLength + '-' * (barLength - filledLength)
    sys.stdout.write('%s [%s] %s%s %s\r' % (prefix, bar, percents, '%', suffix)),
    sys.stdout.flush()
    if iteration == total:
        print("\n")
