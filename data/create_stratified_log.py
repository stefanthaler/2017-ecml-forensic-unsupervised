import argparse     # parse command line ptions
import os
import io

# parse arguments
parser = argparse.ArgumentParser(description='Splits logfile to a number of strata.')
parser.add_argument('-if', '--in_file', type=str, default="bgl2.log", help='') #spirit2.log
parser.add_argument('-ns', '--num_strata', type=int, default=10, help='') #for spirit2 360
parser.add_argument('-of', '--only_first', type=bool, default=True, help='Only create first strata')
args = parser.parse_args()
infile_name = args.in_file

num_strata = args.num_strata


# load infile
in_file = io.open(infile_name, "r", encoding="latin1")

# open outfiles
outfiles = []
if args.only_first:
    print("Only generating first of %i strata"%num_strata)
    out_file_name = infile_name.replace(".", "_%0.2d."%0)
    outfiles.append(open(out_file_name, "w"))
else:
    for i in range(num_strata):
        out_file_name = infile_name.replace(".", "_%0.2d."%i)
        outfiles.append(open(out_file_name, "w"))

# split files to stratas
for i, line in enumerate(in_file):
    if args.only_first:
        if i%num_strata==0:
            outfiles[0].write(line)
    else:
        outfiles[i%num_strata].write(line)

# close
for of in outfiles:
    of.close()

print("Done. Bye bye.")
