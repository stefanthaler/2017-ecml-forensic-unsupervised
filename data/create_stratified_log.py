import argparse     # parse command line ptions

# parse arguments
parser = argparse.ArgumentParser(description='Splits logfile to a number of strata.')
parser.add_argument('-if', '--in_file', type=str, default="bgl2.log", help='')
parser.add_argument('-ns', '--num_strata', type=int, default=10, help='')
args = parser.parse_args()
infile_name = args.in_file
num_strata = args.num_strata

# load infile
in_file_lines =  list(open(infile_name,"r"))

# open outfiles
outfiles = []
for i in xrange(num_strata):
    out_file_name = infile_name.replace(".", "_%0.2d."%i)
    outfiles.append(open(out_file_name, "w"))

# split files to stratas
for i, line in enumerate(in_file_lines):
    outfiles[i%num_strata].write(line)

# close
for of in outfiles:
    of.close()

print("Done. Bye bye.")
