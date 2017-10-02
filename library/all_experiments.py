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
