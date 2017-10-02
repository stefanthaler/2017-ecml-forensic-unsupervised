import argparse     # parse command line ptions
from string import Template # for creating string templates
from collections import namedtuple
import numpy as np
import string
import random
import os
import tokenize
import nltk

Signature = namedtuple('Signature', 'num_vars template identifier')

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
