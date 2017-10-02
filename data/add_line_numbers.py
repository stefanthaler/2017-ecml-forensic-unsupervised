import argparse     # parse command line ptions

# parse arguments
parser = argparse.ArgumentParser(description='Adds line numbers to dataset')
parser.add_argument('-if', '--in_file', type=str, default="bgl2.log", help='')
args = parser.parse_args()
infile_name = args.in_file

in_file = open(infile_name,"r")
o = open(infile_name.replace(".","_ln."),"w")

for i,line in enumerate(in_file):
    o.write("{}\t{}".format(i,line))

in_file.close()
o.close()
print("Done. Bye bye.")
