ALL_EXPERIMENTS = {
    6:"unix_log", # unix system log, 11.023 lines, 856 signatures
    11: "bgl2_00", # every 10th line of bgl2 system log, ~470.000 lines, ~450 signatures, replaced timestamps, node ids etc with placeholder
    13: "spirit2_00" # 770.000 log lines, ~700 signatures
}

EXPERIMENT_LIB_MAPPING = {
    11:"bgl2",
    13:"spirit2",
}

SPLIT_TOKEN ={
    "default":['.', '"' , "'" , ',' , '(', ')', '!', '?', ';', ':', "\\" , '/', '[',']',"=","-",'_' ],
    10:['"'," "],
}


DOWNLOAD_URLS = {
    11: "http://0b4af6cdc2f0c5998459-c0245c5c937c5dedcca3f1764ecc9b2f.r43.cf2.rackcdn.com/hpc4/bgl2.gz",
    13: "http://0b4af6cdc2f0c5998459-c0245c5c937c5dedcca3f1764ecc9b2f.r43.cf2.rackcdn.com/hpc4/spirit2.gz"
}

DOWNLOAD_FN = {
    11:"bgl2.gz",
    13:"spirit2.gz"
}

NUM_STRATA = {
    11:  10,
    13: 380,
}
