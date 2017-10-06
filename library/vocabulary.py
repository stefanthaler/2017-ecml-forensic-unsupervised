import builtins as g
import nltk
import itertools
from library.helpers import save_to_json, load_from_json
import time
import os

if g.REGENERATE_VOCABULARY_FILES or not os.path.exists(g.WORD_TO_INDEX_FILE):

    tokenized_loglines = []

    loglines = list(open(g.datafile, 'r'))
    print("Loaded %i loglines"%len(loglines))
    total_lines = len(loglines) if g.vocabulary_max_lines==-1 else g.vocabulary_max_lines
    start_time = time.time()
    print("Tokenizing %i lines... "%total_lines)
    for i, logline in enumerate(loglines):
        if i==10000:
            print("Estimated time for tokenization ~ %.2f (in min)"%(total_lines *(time.time()-start_time)/10000.0/60.0))
        # decode and to lower
        logline = logline.lower()
        # add start and end token
        for char in g.SPLIT_TOKEN:
            logline = logline.replace(char, ' ' + char + ' ')
        # tokenize
        tokenized_logline = logline.split(" ")[0:200] #nltk.word_tokenize(logline)
        # prepend special token
        tokenized_logline = [g.logline_start_token] + tokenized_logline + [g.logline_end_token]
        # add to array
        tokenized_loglines.append(tokenized_logline)

        if g.vocabulary_max_lines>0 and i>g.vocabulary_max_lines:
            break

    print ("Tokenized logfile.")


    """
        2) Create Vocabulary from tokenized loglines, count word frequencies
    """
    # word frequencies
    word_frequencies = nltk.FreqDist(itertools.chain(*tokenized_loglines))
    vocabulary_size = len(word_frequencies.items())

    # Get the most common words and build index_to_word and word_to_index vectors
    vocabulary = word_frequencies.most_common(vocabulary_size)
    vocabulary = [("PAD_TOKEN", 0) ] + vocabulary
    vocabulary_size+=1 # for pad token


    """
        3) Create index_to_word and word_to_index dictionary
    """
    index_to_word = [word[0] for word in vocabulary]
    index_to_word.append(g.unknown_token)
    word_to_index = dict([(w,i) for i,w in enumerate(index_to_word)])
    print("Created index_to_word and word_to_index dictionary. ")

    """
        4) Replace unknown words with an UNK token (not relevant for us now)
    """
    # replace unknown words with unknown token
    for i, logline in enumerate(tokenized_loglines):
        tokenized_loglines[i] = [w if w in word_to_index else g.unknown_token for w in logline]

    # assign token ids
    PAD_ID = word_to_index[g.pad_token]
    UNK_ID = word_to_index[g.unknown_token]
    BOS_ID = word_to_index[g.logline_start_token]
    EOS_ID = word_to_index[g.logline_end_token]

    if not PAD_ID == 0:
        raise("Padding ID has to be 0, because tensorflow says so and all masking / padding algorithms depend on it")

    save_to_json(vocabulary, g.VOCABULARY_FILE)
    save_to_json(tokenized_loglines, g.TOKENIZED_LOGLINES_FILE)
    save_to_json(index_to_word, g.INDEX_TO_WORD_FILE)
    save_to_json(word_to_index, g.WORD_TO_INDEX_FILE)
else:
    loglines = list(open(g.datafile, 'r'))
    word_to_index=load_from_json(g.WORD_TO_INDEX_FILE)
    index_to_word=load_from_json(g.INDEX_TO_WORD_FILE)
    vocabulary= load_from_json(g.VOCABULARY_FILE)
    vocabulary_size = len(vocabulary)
    tokenized_loglines = load_from_json(g.TOKENIZED_LOGLINES_FILE)
    word_frequencies = nltk.FreqDist(itertools.chain(*tokenized_loglines))
    PAD_ID = word_to_index[g.pad_token]
    UNK_ID = word_to_index[g.unknown_token]
    BOS_ID = word_to_index[g.logline_start_token]
    EOS_ID = word_to_index[g.logline_end_token]
    print("Loaded vocabulary from files")

print ("Tokenized loglines samples:")
for tl in tokenized_loglines[0:5]:
    print("\t%s\n"%tl)
print ("Vocabulary size %d." % vocabulary_size)
print ("PAD_ID\t %d" % PAD_ID)
print ("UNK_ID\t %d" % UNK_ID)
print ("BOS_ID\t %d" % BOS_ID)
print ("EOS_ID\t %d" % EOS_ID)
