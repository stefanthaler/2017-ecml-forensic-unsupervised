"""
    Maps similar events to same id
"""
# imports
import argparse     # parse command line ptions
import csv          # csv files
import re as re    # for regular expressions
import os           # copy to clipboard
import numpy as np  # calculating dataset statistics
import json         # dumping results to file

# copy text to clipboard
import subprocess

def copy2clip(txt):
    cmd='echo "'+txt.strip()+'"| xsel --clipboard'
    return subprocess.check_call(cmd, shell=True)


"""
    Helper pattern
"""
#
hexchar = "[0-9a-fA-F]"
hexcharcol = "[0-9a-fA-F:]"


#
hex_address = "0x%s{8}"%hexchar
ip4address = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
ip4andport ="%s:\d{1,5}"%ip4address

# 1117838570
timestamp = "\d{10}"
# 2005.06.03
date = "20\d{2}?\.\d{2}\.\d{2}"
null_node = "NULL"
unknown_location = "UNKNOWN_LOCATION"

# 2005-06-03-15.42.50.363779
datetime =  "20\d{2}?-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}\.\d{6}"
# R02-M1-N0-C:J12-U11 | R20-M1-NF-C:J13-U01 | R21-M1-N8-C:J10-U01
nodeid = "R\d{2}-M\d-N\w-\w:J\d{2}-U\d{2}"#|%s|%s)"%(null_node, unknown_location)

# R27-M1-L3-U18-C
# R72-M1-L1-U18-A
nodeid2 = "R\d{2}-M\d-L\d-U\d{2}-\w"#%(null_node, unknown_location)
# R33-M1-ND
nodeid3 = "R\d{2}-M\d-?[NL]?\w?\w?"#"|%s|%s|R\d\d)"%(null_node, unknown_location)
#
rack_id = "R\d{2}"

eight_hex = "%s{8}"%hexchar
# \(unit=0x0b bit=0x17\)
unit_id = "\(unit=0x%s{2} bit=0x%s{2}\)"%(hexchar, hexchar)
# FF:F2:9F:16:E8:42:00:0D:60:E9:17:BD
LP_ADDRESS = "%s{35}"%hexcharcol
"""
if split_line[3]=="NULL":
    node_id = "NULL"
elif split_line[3]=="UNKNOWN_LOCATION":
    node_id = "UNKNOWN_LOCATION"
elif re.search(r"R\d{2}-M\d-N\w-\w:J\d{2}-U\d{2}",split_line[3]):
    node_id = "NODE_ID_01"
elif re.search(r"R\d{2}-M\d-L\d-U\d{2}-\w",split_line[3]):
    node_id = "NODE_ID_02"
elif re.search(r"R\d{2}-M\d-?[NL]?\w?",split_line[3]):
    node_id = "NODE_ID_03"
else:
    node_id = split_line[3]
"""

# (bit=0x09): Torus/Tree/GI read error 0
machine_check_interupt_torus_read_error = "machine check interrupt \(bit=0x09\): Torus/Tree/GI read error 0"


# Ido chip status changed: FF:F2:9F:16:E7:14:00:0D:60:E9:18:EB ip=10.1.1.75 v=13 t=4 status=M Fri Jun 17 07:25:00 PDT 2005
# Ido chip status changed: FF:F2:9F:16:EB:8B:00:0D:60:E9:14:74 ip=10.0.0.140 v=13 t=4 status=M Mon Nov 14 07:14:42 PST 2005
ido_chipstatus_changed = "Ido chip status changed: %s{35} ip=%s v=\d{1,2} t=\d status=\w .+? 2\d{3}"%(hexcharcol,ip4address)
# BglIdoChip table has 2 IDOs with the same IP address \(10.0.0.237\)
bgl_ido_chip_table = "BglIdoChip table has \d+? IDOs with the same IP address \(%s\)"%(ip4address)
# SerialNumber\(000000000000000000000000fff29f16e842000d60e917bd\) IpAddress\(10.0.0.237\) Status\(A\)
serialnumber_ipaddress = "SerialNumber\(%s{48}\) IpAddress\(%s\) Status\(\w\)"%(hexchar,ip4address)
# core.304
generating_core = "generating core\.\d{1,5}?"
# 1 ddr errors(s) detected and corrected on rank 0, symbol 0, bit 3
ddr_error_detected_on_rank = "\d{1,3}? ddr errors\(s\) detected and corrected on rank 0, symbol \d{1,2}?, bit \d"
# total of 1 ddr error(s) detected and corrected
total_ddr_errors = "total of \d+? ddr error\(s\) detected and corrected"
# 3450051 L3 EDRAM error(s) (dcr 0x0157) detected and correcte
l3_edram_error="\d{1,10}? L3 EDRAM error\(s\) \(dcr 0x0157\) detected and corrected"
# CE sym 0, at 0x0b8580c0, mask 0x10
ce_sym="CE sym \d{1,2}?, at 0x%s{8}, mask 0x%s{2}"%(hexchar,hexchar)
# ddr: activating redundant bit steering: rank=0 symbol=0
ddr_redundant_bit_steering="ddr: activating redundant bit steering: rank=0 symbol=\d{1,2}?"
#  ddr: excessive soft failures, consider replacing the card
ddr_excessive_soft_failures = "ddr: excessive soft failures, consider replacing the card"
# ciod: Error loading /p/gb2/stella/RAPTOR/65641/raptor: invalid or missing program image, No such file or directory
invalid_missing_program = "ciod: Error loading .+?: invalid or missing program image, No such file or directory"
# 1347195 double-hummer alignment exceptions
double_hummer_exceptions = "\d{1,10}? double-hummer alignment exceptions"
#  ciod: X coordinate 8 exceeds physical dimension 8 at line 17 of node map file /home/fgygi/qb/test/h2o/h2o512/txyz1024.map
ciod_xcoordinate_exceeded = "ciod: [XYTZ] coordinate \d+? exceeds physical dimension \d+? at line \d{1,4} of node map file .+?"
# ciodb exited normally with exit code 0
ciodb_exited_normally = "ciodb exited normally with exit code \d{1,2}"
# ciodb exited abnormally due to signal: Aborted
ciodb_exited_abnormally = "ciodb exited abnormally due to signal: .+?"
# Error receiving packet on tree network, expecting type 57 instead of type 3 (softheader=0064588e 8aff0003 00000002 00000000) PSR0=00001f01 PSR1=00000000 PRXF=00000002 PIXF=00000007
error_receiving_packet_tree="Error receiving packet on tree network, expecting type \d{1,2} instead of type \d{1,2} \(softheader=.+?\) .+?"

#ciod: Error creating node map from file /home/fgygi/qb/test/h2o/h2o512/txyz1024.map: Cannot allocate memory
ciod_error_creating_node_map = "ciod: Error creating node map from file /.+?: Cannot allocate memory"
# NULL DISCOVERY INFO New ido chip inserted into the database: FF:F2:9F:16:EE:CF:00:0D:60:E9:11:30 ip=10.0.0.59 v=13 t=4
new_ido_chipset_inserted = "NULL DISCOVERY INFO New ido chip inserted into the database: .+? ip=%s v=\d{1,2} t=\d"%(ip4address)

# 1 tree receiver 2 in re-synch state event(s) (dcr 0x019a) detected
tree_receiver_detected = "\d{1,8} tree receiver \d in re-synch state event\(s\) \(dcr 0x%s{4}\) detected.*?"%(hexchar)
# idoproxydb has been started: : DRV142_2005 $ Input parameters: -enableflush -loguserinfo db.properties BlueGene1
ido_proxy_has_been_started = "idoproxydb has been started: \$Name: .+? \$ Input parameters: -enableflush -loguserinfo db\.properties BlueGene1"
# ciodb has been restarted.
ciodb_has_been_restarted = "ciodb has been restarted\."
# mmcs_db_server has been started: ./mmcs_db_server --useDatabase BGL --dbproperties serverdb.properties --iolog /bgl/BlueLight/logs/BGL --reconnect-blocks all
# mmcs_db_server has been started: ./mmcs_db_server --useDatabase BGL --dbproperties serverdb.properties --iolog /bgl/BlueLight/logs/BGL --reconnect-blocks all --shutdown-timeout 30
# mmcs_db_server has been started: ./mmcs_db_server --useDatabase BGL --dbproperties db.properties --iolog /bgl/BlueLight/logs/BGL --reconnect-blocks all
mmcs_db_server_started = "mmcs_db_server has been started: .+?/mmcs_db_server --useDatabase BGL --dbproperties .+?\.properties --iolog /bgl/BlueLight/logs/BGL --reconnect-blocks all.*?"

# ciod: failed to read message prefix on control stream
ciod_failed_control_stream = "ciod: failed to read message prefix on control stream \(CioStream socket to 172\.16\.96\.116\:\d{5}"
# 1 L3 directory error(s) (dcr 0x0152) detected and corrected
l3_directory_errors_detected = "\d+? L3 directory error\(s\) \(dcr 0x0152\) detected and corrected"
# instruction address: 0x0000df30
instruction_address = "instruction address: 0x%s{8}"%hexchar
# machine check status register: 0x81000000
machine_check_status = "[mM]achine [cC]heck [Ss]tatus [Rr]egister: 0x%s{8}"%hexchar
# 1:1fefff30 2:1eeeeeee 3:00000000
general_purpose_registers ="(\d{1,2}:%s{8} ?){3,4}?"%(hexchar)
#  lr:003625f0 cr:20000000 xer:00000002 ctr:0037f084
# - 1119454873 2005.06.22 R02-M1-N0-C:J12-U11 2005-06-22-08.41.13.453790 R02-M1-N0-C:J12-U11 RAS KERNEL INFO lr:0047ac04 cr:00000020 xer:20000002 ctr:00000000

special_purpose_registers = "lr:%s{8} cr:%s{8} xer:%s{8} ctr:%s{8}"%(hexchar,hexchar,hexchar,hexchar)
#  17 torus receiver x+ input pipe error(s) (dcr 0x02ec) detected and corrected
torus_reciever_error = "\d{1,10} torus receiver [xyz][\+\-] input pipe error\(s\) \(dcr 0x%s{4}\) detected and corrected.*?"%(hexchar)
# 1 torus sender y- retransmission error(s) (dcr 0x02f7) detected and corrected
torus_sender_corrected = "\d{1,8} torus sender [xyz][\+\-] retransmission error\(s\) \(dcr 0x%s{4}\) detected and corrected"%(hexchar)
# external input interrupt (unit=0x02 bit=0x0b): torus sender y+ retransmission error was corrected
torus_retransmission_corrected = "external input interrupt \(unit=0x%s{2} bit=0x%s{2}\): torus sender [xyz][\+-] retransmission error was corrected"%(hexchar,hexchar)
#  Expected 10 active FanModules, but found 9 ( Found J300 J301 J302 J303 J304 J306 J307 J308 J309 ).
expected_x_fanmodules="Expected \d{1,2} active FanModules, but found \d{1,2} \( Found( .+?)+ \)\."
# data address: 0x4bffffa4
data_address = "data address: 0x%s{8}"%(hexchar)
#  ciod: cpu 0 at treeaddr 925 sent unrecognized message 0xffffffff
ciod_unrecognized_message = "ciod: cpu 0 at treeaddr \d{2,5} sent unrecognized message 0xffffffff"
#  ciod: for node 42, read continuation request but ioState is 0
ciod_read_continuation =  "ciod: for node \d{1,3}, read continuation request but ioState is 0"
# ciod: Message code 2 is not 3 or 4294967295
ciod_message_code = "ciod: Message code \d is not \d{1,2} or 4294967295"
# machine check interrupt (bit=0x1d): L2 dcache unit data parity error
# machine check interrupt (bit=0x10): L2 dcache unit read return parity error

machine_check_interupt_l2  = "machine check interrupt \(bit=0x.+?\): L2 dcache unit data parity error"

machine_check_interupt_l2_cdu  = "machine check interrupt \(bit=0x.+?\): L2 DCU read error"
# ciod: LOGIN chdir(/p/gb1/stella/RAPTOR/2183) failed: Input/output error
ciod_login_input_output = "ciod: LOGIN chdir\(/.+?\) failed: Input/output error"

# machine check interrupt \(bit=0x06\): L3 major internal error
machine_check_interupt_l3 = "machine check interrupt \(bit=0x06\): L3 major internal error"
# L3 global control register: 0x001249f0
l3_global_control_register = "L3 global control register: 0x%s{8}"%(hexchar)
# L3 ecc control register: 00000000
l3_ecc_control_register = "L3 ecc control register: %s{8}"%(hexchar)
# L3 ecc status register: 00000000
l3_ecc_status_register = "L3 ecc status register: %s{8}"%(hexchar)
# mmcs_server exited normally with exit code 13
mmcs_server_exited_normally = "mmcs_server exited normally with exit code \d{1,2}"

# HARDWARE WARNING PrepareForService is being done on this card(mLctn(R33-M1-ND), mCardSernum(203231503833343000000000594c31304b35303034303232), mLp(FF:F2:9F:16:BF:44:00:0D:60:E9:40:BB), mIp(10.3.0.80), mType(4)) by root
hardware_warning = "PrepareForService is being done on this card\(mLctn\(%s\), mCardSernum\(%s+?\), mLp\(.+?\), mIp\(%s\), mType\(4\)\) by root"%(nodeid3,hexchar,ip4address)
# HARDWARE WARNING PrepareForService shutting down NodeCard(mLctn(R33-M1-ND), mCardSernum(203231503833343000000000594c31304b35303034303232), mLp(FF:F2:9F:16:BF:44:00:0D:60:E9:40:BB), mIp(10.3.0.80), mType(4)) as part of Service Action 219
hardware_warning_shutdown =  "PrepareForService shutting down NodeCard\(mLctn\(%s\), mCardSernum\(%s+?\), mLp\(.+?\), mIp\(%s\), mType\(4\)\) as part of Service Action \d{3}"%(nodeid3,hexchar,ip4address)
# PrepareForService is being done on this part \(mLctn\(R36-M1-NE\), mCardSernum\(203231503833343000000000594c31304b3433343231544b\), mLp\(FF:F2:9F:16:C9:63:00:0D:60:E9:36:9C\), mIp\(10.3.1.147\), mType\(4\)\) by root
prepare_for_service_on_this_part = ("PrepareForService is being done on this part \(mLctn\(%s\), "
    "mCardSernum\(.+?\), mLp\(.+?\), mIp\(%s\), "
    "mType\(\d\)\) by .*?")%(nodeid3, ip4address)
# PrepareForService is being done on this Midplane (mLctn(R07-M1), mCardSernum( 203937503631353900000000594c31304b34323635303343)) by root
# PrepareForService is being done on this Midplane (mLctn(R07-M1), mCardSernum( 203937503631353900000000594c31304b34323635303343)) by root
prepare_for_service_on_this_midplane = "PrepareForService is being done on this Midplane \(mLctn\(.+?\), mCardSernum\( .+?\)\) by .+?"
# DDR failing info register: 0x8f401000
ddr_failing_info_register = "DDR failing info register: 0x%s{8}"%(hexchar)
# symbol................15
symbol = "symbol................\d{1,2}"
# mask..................0x00
mask = "mask..................0x%s{2}"%(hexchar)
# 1 torus processor sram reception error\(s\) \(dcr 0x02fc\) detected and corrected
torus_sram_repetition = "\d+? torus processor sram reception error\(s\) \(dcr 0x02fc\) detected and corrected"
# ddr: Unable to steer rank=0, symbol=0 - rank is already steering symbol 2. Due to multiple symbols being over the correctable e
ddr_unable_to_steer_rank = "ddr: Unable to steer rank=0, symbol=\d{1,3} - rank is already steering symbol \d{1,3}. Due to multiple symbols being over the correctable? ?e?"
# ddr: Unable to steer rank=0, symbol=5 - rank is already steering symbol 4. Due to multiple symbols being over the correctable error threshold, consider replacing the card
ddr_unable_to_steer_rank_already_steering = "ddr: Unable to steer rank=0, symbol=\d{1,3} - rank is already steering symbol \d{1,3}. Due to multiple symbols being over the correctable error threshold, consider replacing the card"



"""
    Logline patterns
"""
# according to https://jiemingzhu.github.io/pub/pjhe_dsn2016.pdf, should have 376 events

KNOWN_LOGLINE_PATTERN = [
r"^(-|LINKDISC) TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE WARNING {prepare_for_service_on_this_midplane}$".format(  prepare_for_service_on_this_midplane=prepare_for_service_on_this_midplane),
r"^(-|MASNORM) TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS BGLMASTER FAILURE {ciodb_exited_normally}$".format(ciodb_exited_normally=ciodb_exited_normally),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_01|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_01|UNKNOWN_LOCATION) NULL DISCOVERY WARNING Problem communicating with link card (ido|iDo machine) with LP of {LP_ADDRESS}, caught java.lang.IllegalStateException: while executing I2C Operation caught java.lang.RuntimeException: Communication error: \(DirectIDo for com.ibm.ido.DirectIDo object \[{LP_ADDRESS}@/{ip4andport} with image version \d+? and card type \d+?\] is in state = COMMUNICATION_ERROR, sequenceNumberIsOk = false, ExpectedSequenceNumber = \d+?, Reply Sequence Number = .+?, timedOut = true, retries = 200, timeout = 1000, Expected Op Command = 2, Actual Op Reply = -1, Expected Sync Command = .+?, Actual Sync Reply = .+?\)$".format(hexchar=hexchar, hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_01|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_01|UNKNOWN_LOCATION) {new_ido_chipset_inserted}$".format(   new_ido_chipset_inserted=new_ido_chipset_inserted),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|NULL) DATE_TIME (NODE_ID_03|NULL) RAS MMCS ERROR idoproxydb hit ASSERT condition: ASSERT expression=.+? Source file=.+? Source line=\d+? Function=.+? .+?::.+?\)$".format(hexchar=hexchar, hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY ERROR Bad cable going into LinkCard \({hexchar}+?\) Jtag \(\d\) Port \(\w\) - \d+? bad wires".format(hexchar=hexchar, hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY ERROR Missing reverse cable: Cable {nodeid3} \d \w \(J\d+?\) --> {nodeid3} \d \w \(J\d+?\) is present BUT the reverse cable {nodeid3} \d \w \(J\d+?\) --> {nodeid3} \d \w \(J\d+?\) is missing".format(hexchar=hexchar, hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY INFO Node card VPD check: missing U\d+? node, VPD ecid {hexchar}+? in processor card slot J\d+?$".format(hexchar=hexchar, hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY (INFO|WARNING) Node card VPD check: U\d+? node in processor card slot J\d+? do not match. VPD ecid {hexchar}+?, found {hexchar}+?$".format(hexchar=hexchar),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY SEVERE Can not get assembly information for node card$",
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY SEVERE Problem communicating with service card, ido chip: {hexcharcol}+?\. java.io.IOException: Could not find EthernetSwitch on port:address \d+?:\d+?$".format(hexcharcol=hexcharcol, hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY SEVERE {expected_x_fanmodules}$".format(   expected_x_fanmodules=expected_x_fanmodules),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL (DISCOVERY|HARDWARE) (WARNING|SEVERE) (Node card|NodeCard) is not fully functional$",
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY WARNING Problem communicating with service card, ido chip: {hexcharcol}+?\. java.lang.IllegalStateException: IDo is not in functional state -- currently in state COMMUNICATION_ERROR$".format(hexcharcol=hexcharcol),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY WARNING this link card is not fully functional$".format(LP_ADDRESS=LP_ADDRESS,ip4address=ip4address),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL HARDWARE SEVERE LinkCard is not fully functional$".format( LP_ADDRESS=LP_ADDRESS,ip4address=ip4address),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL HARDWARE SEVERE LinkCard power module U\d+? is not accessible$".format( LP_ADDRESS=LP_ADDRESS,ip4address=ip4address),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION|{rack_id}) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION|{rack_id}) NULL HARDWARE WARNING EndServiceAction \d\d\d performed upon {rack_id} by .+?$".format(rack_id=rack_id,   ),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|{rack_id}|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|{rack_id}|UNKNOWN_LOCATION) NULL HARDWARE WARNING PrepareForService is being done on this rack \({rack_id}\) by .+?$".format(rack_id=rack_id,   ),
r"^- TIME_STAMP SHORT_DATE - DATE_TIME 0 \(.+?\) iar {hex_address}, dear {hex_address} \(.+? RAS KERNEL INFO Kernel.*?$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE - DATE_TIME nput interrupts, 0 microseconds max time in a cr RAS KERNEL INFO .+? total interrupts. .+? critical input interrupts. .+? microseconds total spent on critical input interrupts, .+? microseconds max time in a critical input interrupt.$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE - DATE_TIME RAS KERNEL FATAL Kill job \d\d\d\d\d timed out. Block freed.$",
r"^- TIME_STAMP SHORT_DATE - DATE_TIME time for a single instance of a correctable ddr. RAS KERNEL INFO .+? microseconds spent in the rbs signal handler during .+? calls. .+? microseconds was the maximum time for a single instance of a correctable ddr.*?$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE (NODE_ID_01|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_01|UNKNOWN_LOCATION) NULL HARDWARE WARNING .+?IBM Part Number:.+?Vendor:.+?$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: Error creating node map from file .+?: .+?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: Error loading .+?: invalid or missing program image, .+?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: Error loading .+?: not a CNK program image$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: Error loading .+?: program image too big, .+? > .+?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: LOGIN open\(.+?\) failed: Permission denied$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL DCR 0x\w\w\w : {hex_address}$".format(hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL Torus non-recoverable error DCRs follow.$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: LOGIN chdir\(.+?\) failed: .+?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL [Cc]ore [Cc]onfiguration [Rr]egister.*?: {hex_address}$".format(hex_address=hex_address,   ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL [Gg]eneral [Pp]urpose [Rr]egisters:$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL \d*?, max=\d+?$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL \d+?$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL address parity error..0$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL auxiliary processor.........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL byte ordering exception.....................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL capture first DDR uncorrectable error address..[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL capture first directory correctable error address..[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL capture first directory uncorrectable error address..[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL capture first EDRAM correctable error address..[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL capture first EDRAM parity error address..[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL capture first EDRAM uncorrectable error address..[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL capture valid.........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL CHECK_INITIAL_GLOBAL_INTERRUPT_VALUES$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL chip select...........0$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL close EDRAM pages as soon as possible....[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL command manager unit summary.....................0$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL correctable error detected in directory [01]......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL correctable error detected in EDRAM bank [01].....[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL correctable error.....[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL critical input interrupt enable...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL d-cache flush parity error........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL d-cache search parity error.......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL data address space................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL data read plb error...............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL data store interrupt caused by \w\w\w\w.........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL data write plb error..............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL dbcr0={hex_address} dbsr={hex_address} ccr0={hex_address}$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL DDR failing address register: {hex_address} {hex_address}$".format(   hex_address=hex_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL DDR failing data registers: {hex_address} {hex_address}$".format(   hex_address=hex_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL DDR failing info register: DDR Fail Info Register: {hex_address}$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL ddrSize == .*? \|\| ddrSize == .*?$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL debug interrupt enable............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL debug wait enable.................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL disable all access to cache directory....[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL disable apu instruction broadcast........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL disable flagging of DDR UE's as major internal error.[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL disable speculative access...............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL disable store gathering..................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL disable trace broadcast..................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL disable write lines 2:4..................[10]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL divide-by-zero exception.................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL enable divide-by-zero exceptions.........[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL enable inexact exceptions................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL enable invalid operation exceptions......[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL enable non-IEEE mode.....................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL enable overflow exceptions...............[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL enable underflow exceptions..............[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL enabled exception summary................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL Error sending packet on tree network, packet at address {eight_hex} is not aligned$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL exception summary........................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL exception syndrome register: {hex_address}$".format(  hex_address=hex_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL external input interrupt enable...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL floating point instr. enabled.....[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL floating point operation....................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL Floating Point Registers:$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL Floating Point Status and Control Register: {hex_address}$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL floating pt ex mode 0 enable......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL floating pt ex mode 1 enable......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL force load/store alignment...............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL fpr.+?={hex_address} {eight_hex} {eight_hex} {eight_hex}$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL fraction inexact.........................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL fraction rounded.........................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL gister: machine state register: machine state register: machine state register: machine state register: machine state register:$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL guaranteed data cache block touch........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL guaranteed instruction cache block touch.[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL i-cache parity error..............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL icache prefetch depth....................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL icache prefetch threshold................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL imprecise machine check...........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL inexact exception........................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL instruction address space.........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL instruction plb error.............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL interrupt threshold...0$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL invalid \(compare\)........................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL invalid \(Inf/Zero\).......................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL invalid \(Inf[-/]Inf\)........................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL invalid \(SNAN\)...........................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL invalid \(Zero/Zero\)......................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL invalid operation exception \(int cnvt\)...[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL invalid operation exception \(software\)...[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL invalid operation exception \(sqrt\).......[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL invalid operation exception summary......[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL lr={hex_address} cr={hex_address} xer={hex_address} ctr={hex_address}$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL m?a?x=\d+?$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL machine check enable..............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL machine check summary.............[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL machine check: i-fetch......................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL machine state register: machine state register: machine state register: machine state register: machine state register: machine$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL MailboxMonitor::serviceMailboxes\(\) lib_ido_error: -1114 unexpected socket error: Broken pipe$".format(hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL max number of outstanding prefetches.....\d$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory and bus summary...........................0$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory manager / command manager address parity..[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory manager address error.....................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory manager address parity error..............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory manager miscompare........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory manager refresh...........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory manager RMW buffer parity.................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory manager store buffer parity...............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory manager strobe gate.......................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL memory manager uncorrectable error...............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL minus denormalized number................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL minus inf................................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL minus normalized number..................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL minus zero...............................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL miscompare............0$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL msr={hex_address} dear={hex_address} esr={hex_address} fpscr={hex_address}$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL number of correctable errors detected in L3 directories...0$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL number of correctable errors detected in L3 EDRAMs.........+?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL number of lines with parity errors written to L3 EDRAMs...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL overflow exception.......................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL parity error in bank [01].........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL parity error in read queue [01]...................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL parity error in read queue PLB.................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL parity error in write buffer...................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL parity error.......[01]$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL plus denormalized number.................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL plus infinity............................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL plus normalized number...................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL plus zero................................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL prefetch depth for core \d................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL prefetch depth for PLB slave.............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL pro(gram)?$".format(   ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL problem state \(0=sup,1=usr\).......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL program interrupt: fp compare...............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL program interrupt: fp cr field .............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL program interrupt: fp cr update.............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL program interrupt: illegal instruction......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL program interrupt: imprecise exception......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL program interrupt: privileged instruction...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL program interrupt: trap instruction.........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL program interrupt: unimplemented operation..[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL quiet NaN................................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL qw trapped............0$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL r.+?={hex_address} r.+?={hex_address} r.+?={hex_address} r.+?={hex_address}$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL regctl scancom interface.........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL reserved.................................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL round nearest............................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL round toward -infinity...................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL round toward \+infinity...................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL round toward zero........................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL rts internal error$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL rts tree/torus link training failed: wanted: .+? got: .+?$".format(   ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL rts: bad message header: .+? \(softheader=.+?\) PSR0={eight_hex} PSR1={eight_hex} PRXF={eight_hex} PIXF={eight_hex}$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL size of DDR we are caching...............1 \(512M\)$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL size of scratchpad portion of L3.........[01] \(0M\)$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL special purpose registers:$".format(  general_purpose_registers=general_purpose_registers),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL start flushing...........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL start initialization.....................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL start prefetching........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL start retagging..........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL state machine....................................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL machine state register:$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL state register: machine state register: machine state register: machine state register: machine state register: machine state re$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL store operation.............................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL summary...........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL Target=ido://{LP_ADDRESS}/JTAG/\d+? Message=.+?$".format(   LP_ADDRESS=LP_ADDRESS),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL tlb error.........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL turn on hidden refreshes.................[10]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL uncorrectable error detected in directory [01]....[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL uncorrectable error detected in EDRAM bank [01]...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL uncorrectable error detected in external DDR...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL uncorrectable error...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL underflow exception......................[01]$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL VALIDATE_LOAD_IMAGE_CRC_IN_DRAM$".format(hexchar=hexchar, hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL wait state enable.................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL write buffer commit threshold............2$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {data_address}$".format(   data_address=data_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {ddr_failing_info_register}$".format(   ddr_failing_info_register=ddr_failing_info_register),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {general_purpose_registers}$".format(  general_purpose_registers=general_purpose_registers),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {hex_address} {hex_address}$".format(   hex_address=hex_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {instruction_address}$".format(   instruction_address=instruction_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {l3_ecc_control_register}$".format(  l3_ecc_control_register=l3_ecc_control_register),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {l3_ecc_status_register}$".format(   l3_ecc_status_register=l3_ecc_status_register),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {l3_global_control_register}$".format(  l3_global_control_register=l3_global_control_register),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {machine_check_status}$".format(  machine_check_status=machine_check_status),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL (FATAL|INFO) [Mm]achine [sS]tate [Rr]egister: {hex_address}$".format(hex_address=hex_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {mask}$".format(  mask=mask),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {special_purpose_registers}$".format(  special_purpose_registers=special_purpose_registers),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {symbol}$".format(  symbol=symbol),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL {torus_retransmission_corrected}$".format(   torus_retransmission_corrected=torus_retransmission_corrected),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? ddr error\(s\) detected and corrected on rank .+?, symbol .+? over .+? seconds$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? L3 directory error\(s\) \(dcr 0x.+?\) detected and corrected over .+? seconds$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? L3 EDRAM error\(s\) \(dcr 0x.+?\) detected and corrected over .+? seconds$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? microseconds spent in the rbs signal handler during .+? calls. .+? microseconds was the maximum time for a single instance of a correctable ddr.$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? torus non-crc error\(s\) \(dcr 0x.+?\) detected and corrected over .+? seconds$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? torus processor sram injection error\(s\) \(dcr 0x.+?\) detected and corrected over .+? seconds$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? torus processor sram reception error\(s\) \(dcr 0x02fc\) detected and corrected over .+? seconds$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? torus receiver sram ecc error\(s\) \(dcr 0x.+?\) detected and corrected over .+? seconds$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? torus sender .+? retransmission error\(s\) \(dcr 0x.+\) detected and corrected over .+? seconds$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4address=ip4address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? torus sender sram ecc error\(s\) \(dcr .+?\) detected and corrected$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO .+? total interrupts. .+? critical input interrupts. .+? microseconds total spent on critical input interrupts, .+? microseconds max time in a critical input interrupt.$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO \d+? floating point alignment exceptions$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO \d+? torus non-crc error\(s\) \(dcr 0x02fd\) detected and corrected$".format(   LP_ADDRESS=LP_ADDRESS),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO auxiliary processor.........................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO byte ordering exception.....................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: duplicate canonical-rank \d+? to logical-rank \d mapping at line \d of node map file /.+?$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: Error opening node map file .+?, No such file or directory$".format(   LP_ADDRESS=LP_ADDRESS),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: for node .+?, incomplete data written to core file core.+?$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: generated \d+? core files for program .+?$".format(   ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: In packet from node .+? \({nodeid}\), message still ready for node .+? \(softheader=.+?\)$".format(nodeid=nodeid,hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: In packet from node \d+?.\d \({nodeid}\), message code \d is not \d or 4294967295 \(softheader={eight_hex} {eight_hex} {eight_hex} {eight_hex}\)$".format(nodeid=nodeid,   eight_hex=eight_hex),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: Missing or invalid fields on line \d+? of node map file /.+?$".format(   eight_hex=eight_hex),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: pollControlDescriptors: Detected the debugger died\.$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: Received signal .+?, code=.+?, errno=.+?, address={hex_address}$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: sendMsgToDebugger: error sending PROGRAM_EXITED message to debugger.$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ciod: Unexpected eof at line \d+? of node map file .+?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO core configuration register: {hex_address}$".format(   hex_address=hex_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO critical input interrupt \(unit=0x.+? bit=0x.+?\): warning for .+? wire, suppressing further interrupts of same type$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO critical input interrupt enable...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO critical input interrupt {unit_id}: warning for .+? wire$".format(   unit_id=unit_id),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO data address space................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO data cache flush parity error detected. attempting to correct$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO data cache search parity error detected. attempting to correct$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO data storage interrupt$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO data store interrupt caused by \w+?.........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ddr: activating redundant bit steering for next allocation: rank=.+? symbol=.+?$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO ddr: Suppressing further CE interrupts$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO debug interrupt enable............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO debug wait enable.................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO disable apu instruction broadcast........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO disable store gathering..................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO disable trace broadcast..................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO e error threshold, consider replacing the card$".format(   LP_ADDRESS=LP_ADDRESS),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO e?rror threshold, consider replacing the card$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO exception syndrome register: {hex_address}$".format(   hex_address=hex_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO external input interrupt \(unit=0x.+? bit=0x.+?\): .+? tree receiver .+? in resynch mode$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO external input interrupt \(unit=0x.+? bit=0x.+?\): number of corrected SRAM errors has exceeded threshold.*?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO external input interrupt enable...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO floating point instr. enabled.....[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO floating point operation....................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO floating pt ex mode \d enable......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO force load/store alignment...............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO general purpose registers:$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO guaranteed data cache block touch........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO guaranteed instruction cache block touch.[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO iar {eight_hex} dear {eight_hex}$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO icache prefetch depth....................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO icache prefetch threshold................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO instruction address space.........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO instruction cache parity error corrected$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO Kernel detected .+? integer alignment exceptions.*?$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO L1 DCACHE summary averages: #ofDirtyLines: .+? out of .+? #ofDirtyDblWord: .+? out of .+?$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO L3 correctable errors exceeds threshold \(iar {hex_address} lr {hex_address}\)$".format(hex_address=hex_address,   ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO MACHINE CHECK DCR read timeout \(mc=.+? iar {hex_address} lr {hex_address}\)$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO machine check enable..............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO MACHINE CHECK PLB write IRQ \(mc=.+? iar {hex_address} lr {hex_address}\)$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO machine check: i-fetch......................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO Microloader Assertion$".format(   ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO NFS Mount failed on .+?, slept .+? seconds, retrying \(.+?\)$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO problem state \(0=sup,1=usr\).......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO program interrupt$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO program interrupt: fp compare...............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO program interrupt: fp cr field .............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO program interrupt: fp cr update.............[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO program interrupt: illegal instruction......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO program interrupt: imprecise exception......[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO program interrupt: privileged instruction...[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO program interrupt: trap instruction.........[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO program interrupt: unimplemented operation..[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO shutdown complete$".format(   LP_ADDRESS=LP_ADDRESS),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO special purpose registers:$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO SRAM correctable errors exceeds threshold \(iar {hex_address} lr {hex_address}\)$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO store operation.............................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO suppressing further interrupts of same type$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO total of .+? ddr error\(s\) detected and corrected over .+? seconds$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO wait state enable.................[01]$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ce_sym}$".format(  ce_sym = ce_sym),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ciod_message_code}$".format(  ciod_message_code=ciod_message_code),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ciod_read_continuation}$".format(  ciod_read_continuation=ciod_read_continuation),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ciod_unrecognized_message}$".format(  ciod_unrecognized_message=ciod_unrecognized_message),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ciod_xcoordinate_exceeded}$".format(   ciod_xcoordinate_exceeded=ciod_xcoordinate_exceeded),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {data_address}$".format(  data_address=data_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ddr_error_detected_on_rank}$".format(  ddr_error_detected_on_rank = ddr_error_detected_on_rank),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ddr_redundant_bit_steering}$".format(  ddr_redundant_bit_steering = ddr_redundant_bit_steering),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ddr_unable_to_steer_rank}$".format(   ddr_unable_to_steer_rank=ddr_unable_to_steer_rank),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {double_hummer_exceptions}$".format(  double_hummer_exceptions = double_hummer_exceptions),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {general_purpose_registers}$".format(   general_purpose_registers=general_purpose_registers),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {generating_core}$".format(  generating_core=generating_core),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {instruction_address}$".format(  instruction_address=instruction_address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {l3_directory_errors_detected}$".format(   l3_directory_errors_detected=l3_directory_errors_detected),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {l3_edram_error}$".format(  l3_edram_error = l3_edram_error),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {special_purpose_registers}$".format(   special_purpose_registers=special_purpose_registers),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {torus_reciever_error}$".format(  torus_reciever_error=torus_reciever_error),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {torus_sender_corrected}$".format(  torus_sender_corrected=torus_sender_corrected),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {torus_sram_repetition}$".format(   torus_sram_repetition=torus_sram_repetition),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {total_ddr_errors}$".format(  total_ddr_errors = total_ddr_errors),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {tree_receiver_detected}$".format(  tree_receiver_detected = tree_receiver_detected),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO$".format(eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO.+? torus receiver sram ecc error\(s\) \(dcr 0x.+?\) detected and corrected$".format(   ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_02 DATE_TIME NODE_ID_02 RAS LINKCARD INFO MidplaneSwitchController performing bit sparing on {nodeid2} bit \d+?$".format(nodeid2=nodeid2,  ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL DISCOVERY ERROR Found invalid node ecid in processor card slot J\d+?, ecid {hexchar}+?$".format(hexchar=hexchar, hex_address=hex_address,    LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
# - TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL DISCOVERY ERROR Node card status: no ALERTs are active. Clock Mode is Low. Clock Select is Midplane. Phy JTAG Reset is asserted. ASIC JTAG Reset is asserted. Temperature Mask is not active. No temperature error. Temperature Limit Error Latch is clear. PGOOD IS NOT ASSERTED. PGOOD ERROR LATCH IS ACTIVE. MPGOOD IS NOT OK. MPGOOD ERROR LATCH IS ACTIVE. The 2.5 volt rail is OK. The 1.5 volt rail is OK.
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL DISCOVERY ERROR Node card status: .+?active\. Clock Mode.*?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL DISCOVERY SEVERE Problem reading the ethernet arl entries fro the service card: java.lang.IllegalStateException: while executing I2C Operation caught java.lang.RuntimeException: Communication error: \(DirectIDo for com.ibm.ido.DirectIDo object \[{LP_ADDRESS}\@/{ip4andport} with image version 9 and card type 2\] is in state = COMMUNICATION_ERROR, sequenceNumberIsOk = false, ExpectedSequenceNumber = .+?, Reply Sequence Number = .+?, timedOut = true, retries = 200, timeout = 1000, Expected Op Command = .+?, Actual Op Reply = .+?, Expected Sync Command = .+?, Actual Sync Reply = .+?\)$".format(   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport, nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE SEVERE NodeCard power module U\d\d is not accessible$".format(  ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE WARNING EndServiceAction \d+?.*? performed upon {nodeid3} by .+?$".format( nodeid3=nodeid3, ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE WARNING EndServiceAction is restarting the (Link cards|LinkCards) in [mM]idplane {nodeid3} as part of Service Action \d+?$".format(nodeid3=nodeid3, hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE WARNING PrepareForService is being done on this Midplane \(mLctn\({nodeid3}\), mCardSernum\(.+?\), iWhichCardsToPwrOff\(.+?\)\) by .+?$".format(hex_address=hex_address, eight_hex=eight_hex,  nodeid3=nodeid3,  ),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE WARNING PrepareForService shutting down (LinkCard|Link card)\(mLctn\({nodeid3}\), mCardSernum\(\w+?\), mLp\({LP_ADDRESS}\), mIp\({ip4address}\), mType\(.*?\)\) as part of Service Action \d+?$".format( nodeid3=nodeid3,  LP_ADDRESS=LP_ADDRESS,ip4address=ip4address),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE WARNING PrepareForService shutting down Node card\(mLctn\({nodeid3}\), mCardSernum\(.+?\), mLp\({hexcharcol}+?\), mIp\({ip4address}\), mType\(.+?\)\) as part of Service Action .+?$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4address=ip4address, eight_hex=eight_hex,  nodeid3=nodeid3,  ),
# - TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL HARDWARE WARNING EndServiceAction is restarting the NodeCards in midplane R33-M1 as part of Service Action 219
r"^- TIME_STAMP SHORT_DATE (NODE_ID_03|UNKNOWN_LOCATION) DATE_TIME (NODE_ID_03|UNKNOWN_LOCATION) NULL HARDWARE WARNING EndServiceAction is restarting the (NodeCards|Node cards) in midplane {nodeid3} as part of Service Action \d+?$".format(nodeid3=nodeid3),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE WARNING {hardware_warning_shutdown}$".format( hardware_warning_shutdown= hardware_warning_shutdown),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE WARNING {hardware_warning}$".format(   hardware_warning= hardware_warning),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL HARDWARE WARNING {prepare_for_service_on_this_part}$".format(   prepare_for_service_on_this_part=prepare_for_service_on_this_part),
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE (Hardware )?monitor caught java.lang.IllegalStateException: while executing .+? Operation caught java.net.SocketException: Broken pipe and is stopping$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE (Hardware )?monitor caught java.net.SocketException: Broken pipe and is stopping$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE Link PGOOD error latched on link card$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE Local PGOOD error latched on link card$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE Temperature Over Limit on link card$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE While reading FanModule caught java.lang.IllegalStateException: while executing I2C Operation .*?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE While setting fan speed caught java.lang.IllegalStateException: while executing I2C Operation .*?$",
r"^- TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR SEVERE Hardware monitor caught java.net.SocketException: Broken pipe and is stopping$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,  nodeid3=nodeid3,  ),
r"^- TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS BGLMASTER FAILURE idoproxy exited normally with exit code 0$".format(  ),
r"^- TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS BGLMASTER INFO BGLMaster has been started: ./BGLMaster --consoleip 127.0.0.1 --consoleport 32035 --configfile bglmaster.init.*?$",
r"^- TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS MMCS ERROR Ido packet timeout$",
r"^- TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS MMCS INFO {ciodb_has_been_restarted}$".format( ciodb_has_been_restarted=ciodb_has_been_restarted),
r"^- TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS MMCS INFO {ido_proxy_has_been_started}$".format( ido_proxy_has_been_started = ido_proxy_has_been_started),
r"^- TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS MMCS INFO {mmcs_db_server_started}$".format( mmcs_db_server_started=mmcs_db_server_started),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL CMCS INFO Controlling BG/L rows \[( \d)+ \]$",
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL CMCS INFO Running as background command$",
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL CMCS INFO Starting SystemController$",
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL DISCOVERY INFO {ido_chipstatus_changed}$".format(  ido_chipstatus_changed=ido_chipstatus_changed),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL DISCOVERY SEVERE Error getting detailed hw info for node, caught java.io.IOException: .*?$",
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL DISCOVERY SEVERE {bgl_ido_chip_table}$".format(  bgl_ido_chip_table=bgl_ido_chip_table),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL DISCOVERY SEVERE {serialnumber_ipaddress}$".format(  serialnumber_ipaddress=serialnumber_ipaddress),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL DISCOVERY WARNING Problem communicating with service card, ido chip: {hexcharcol}+?\. java.lang.IllegalStateException: while executing CONTROL Operation caught java.lang.RuntimeException: Communication error: \(DirectIDo for com.ibm.ido.DirectIDo object \[{LP_ADDRESS}@/{ip4andport} with image version \d+? and card type \d+?] is in state = COMMUNICATION_ERROR, sequenceNumberIsOk = false, ExpectedSequenceNumber = .+?, Reply Sequence Number = .+?, timedOut = true, retries = 200, timeout = 1000, Expected Op Command = .+?, Actual Op Reply = .+?, Expected Sync Command = .+?, Actual Sync Reply = .+?\)$".format(hexcharcol=hexcharcol,   LP_ADDRESS=LP_ADDRESS, ip4andport=ip4andport),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL HARDWARE SEVERE NodeCard power module U\d\d is not accessible$".format(  ),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL HARDWARE SEVERE NodeCard temperature sensor chip U\d\d is not accessible$",
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL HARDWARE SEVERE NodeCard VPD chip is not accessible$",
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL HARDWARE SEVERE NodeCard VPD is corrupt$",
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL HARDWARE WARNING EndServiceAction \d+?.*? performed upon {nodeid3} by .+?$".format( nodeid3=nodeid3, ),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL HARDWARE WARNING EndServiceAction is restarting the LinkCards in midplane {nodeid3} as part of Service Action \d\d\d$".format( nodeid3=nodeid3, ),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL HARDWARE WARNING EndServiceAction is restarting the (NodeCards|Node cards) in midplane {nodeid3} as part of Service Action \d+?$",
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL SERV_NET ERROR DeclareServiceNetworkCharacteristics has been run with the force option but the DB is not empty$".format(   ip4andport=ip4andport),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL SERV_NET INFO Added 8 subnets and 409600 addresses to DB$".format(   ip4andport=ip4andport),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL SERV_NET WARNING DeclareServiceNetworkCharacteristics has been run but the DB is not empty$".format(   ip4andport=ip4andport),
r"^(APPALLOC|APPBUSY|APPCHILD) TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: Error creating node map from file .+?: .+?$",
r"^APP.+? TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL {ciod_login_input_output}$".format(   ciod_login_input_output=ciod_login_input_output),
r"^APPREAD TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: failed to read message prefix on control stream \(CioStream socket to {ip4andport}".format( ip4andport=ip4andport),
r"^APP.+? TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: Error reading message prefix after .+? on CioStream socket to {ip4andport}: .+?$".format(   ip4andport=ip4andport),
r"^APP.+? TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: Error reading message prefix on CioStream socket to {ip4andport}, .+?$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^APPTORUS TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL external input interrupt \(unit=0x02 bit=0x00\): uncorrectable torus error$",
r"^APPUNAV TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS APP FATAL ciod: Error creating node map from file /.+?: Resource temporarily unavailable$",
r"^KERNBIT TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL ddr: redundant bit steering failed, sequencer timeout$",
r"^KERNCON TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL idoproxy communication failure: BGLERR_IDO_PKT_TIMEOUT connection lost to node/link/service card$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^KERNCON TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL MailboxMonitor::serviceMailboxes\(\) lib_ido_error: -1033 BGLERR_IDO_PKT_TIMEOUT connection lost to node/link/service card$",
r"^KERNDTLB TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL data TLB error interrupt$",
r"^KERNEXT TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL external input interrupt \(unit=0x.+? bit=0x.+?\): tree header with no target waiting$",
r"^KERNFLOAT TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL floating point unavailable interrupt$",
r"^KERNMC TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL DDR machine check register: {hex_address} {hex_address}$".format(hex_address=hex_address,   ),
r"^KERNMC TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL machine check interrupt.*?$",
r"^KERNMICRO TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL Microloader Assertion$",
r"^KERNMNT TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL Error: unable to mount filesystem$",
r"^KERNMNTF TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL Lustre mount FAILED : .+? .+?",
r"^KERNNOETH TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL no ethernet link$",
r"^KERNPAN TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL kernel panic$",
r"^KERNPOW TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS KERNEL FATAL Power deactivated: {nodeid3}$".format( nodeid3=nodeid3, ),
r"^KERNPROG TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL program interrupt$",
r"^KERNREC TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL Error receiving packet on tree network.*?$".format(hex_address=hex_address,hexcharcol=hexcharcol, ip4andport=ip4andport, eight_hex=eight_hex,    ),
r"^KERNRTSA TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL rts assertion failed: .*?$",
r"^KERNRTSP TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL rts panic! - stopping execution$",
r"^KERNSERV TIME_STAMP SHORT_DATE (NODE_ID_01|NULL) DATE_TIME (NODE_ID_01|NULL) RAS KERNEL FATAL Power Good signal deactivated: {nodeid3}. A service action may be required.$".format(nodeid3=nodeid3),
r"^KERNSOCK TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL idoproxy communication failure: socket closed$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^KERNSOCK TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL MailboxMonitor::serviceMailboxes\(\) lib_ido_error: -1019 socket closed$",
r"^KERNSTOR TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL data storage interrupt$",
r"^KERNTERM TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL rts: kernel terminated for reason .*?$",
r"^KERNTLBE TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL FATAL instruction TLB error interrupt$".format(   ip4andport=ip4andport),
r"^LINKBLL TIME_STAMP SHORT_DATE NODE_ID_02 DATE_TIME NODE_ID_02 RAS LINKCARD FATAL MidplaneSwitchController::clearPort\(\) bll_clear_port failed: {nodeid2}$".format( nodeid2=nodeid2,  ip4andport=ip4andport),
r"^LINKDISC TIME_STAMP SHORT_DATE NODE_ID_02 DATE_TIME NODE_ID_02 RAS LINKCARD FATAL MidplaneSwitchController::sendTrain\(\) port disconnected: {nodeid2}$".format( nodeid2=nodeid2, ),
r"^LINKIAP TIME_STAMP SHORT_DATE NODE_ID_02 DATE_TIME NODE_ID_02 RAS LINKCARD FATAL MidplaneSwitchController::receiveTrain\(\) iap failed: {nodeid2}, status={eight_hex} {eight_hex}$".format(eight_hex=eight_hex,  nodeid2=nodeid2, ),
r"^LINKPAP TIME_STAMP SHORT_DATE NODE_ID_02 DATE_TIME NODE_ID_02 RAS LINKCARD FATAL MidplaneSwitchController::parityAlignment\(\) pap failed: {nodeid2}, status={eight_hex} {eight_hex}$".format(eight_hex=eight_hex,    nodeid2=nodeid2),
r"^MASABNORM TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS BGLMASTER FAILURE mmcs_server exited abnormally due to signal: .+?$",
r"^MASABNORM TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS BGLMASTER FAILURE {ciodb_exited_abnormally}$".format(ciodb_exited_abnormally=ciodb_exited_abnormally),
r"^MASNORM TIME_STAMP SHORT_DATE NULL DATE_TIME NULL RAS BGLMASTER FAILURE {mmcs_server_exited_normally}$".format(   mmcs_server_exited_normally=mmcs_server_exited_normally),
r"^MMCS TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS MMCS FATAL L3 major internal error$",
r"^MONILL TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE monitor caught java.lang.IllegalStateException: while executing CONTROL Operation caught java.io.EOFException and is stopping$",
r"^MONNULL TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE While inserting monitor info into DB caught java.lang.NullPointerException$".format(   ip4andport=ip4andport),
r"^MONPOW TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE monitor caught java.lang.UnsupportedOperationException: power module U\d\d not present and is stopping$".format(   ip4andport=ip4andport),
r"^MONPOW TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE No power module U.+? found found on link card$".format(hex_address=hex_address, eight_hex=eight_hex,    ),
r"^MONPOW TIME_STAMP SHORT_DATE NODE_ID_03 DATE_TIME NODE_ID_03 NULL MONITOR FAILURE power module status fault detected on node card. status registers are: .+?$".format(eight_hex=eight_hex,    ),
r"^R_DDR_EXC TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ddr_excessive_soft_failures}$".format(  ddr_excessive_soft_failures = ddr_excessive_soft_failures),
r"^R_DDR_STR TIME_STAMP SHORT_DATE NODE_ID_01 DATE_TIME NODE_ID_01 RAS KERNEL INFO {ddr_unable_to_steer_rank_already_steering}$".format(ddr_unable_to_steer_rank_already_steering=ddr_unable_to_steer_rank_already_steering),

r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL DISCOVERY (WARNING|SEVERE) While initializing .+? card.*?$".format(LP_ADDRESS=LP_ADDRESS),
r"^- TIME_STAMP SHORT_DATE UNKNOWN_LOCATION DATE_TIME UNKNOWN_LOCATION NULL DISCOVERY (WARNING|SEVERE) Problem communicating with node card, iDo machine with LP of {LP_ADDRESS} caught java.lang.IllegalStateException: while executing .+? Operation .*?$".format(LP_ADDRESS=LP_ADDRESS),
]

# initializing_node_caught_exception
# compile regular expression for faster execution (patterns get cached)
signatures_by_id = {}
for pattern_id, pattern in enumerate(KNOWN_LOGLINE_PATTERN):
    try:

        KNOWN_LOGLINE_PATTERN[pattern_id]=re.compile(pattern, re.IGNORECASE)
        signatures_by_id[pattern_id+1]=pattern # pattern_id + 1 because 0 is reserved
    except :
        print(pattern_id, pattern)
def extract_pattern_id(message):
    for pattern_id, pattern in enumerate(KNOWN_LOGLINE_PATTERN):
        #print message, pattern
        if re.search(pattern, message):
            return pattern_id+1 # pattern_id + 1 because 0 is reserved
    return 0 # no pattern to parse log line, unknown message

# Print iterations progress
def print_progress (iteration, total, prefix = '', suffix = '', decimals = 2, barLength = 100):
    import sys
    filledLength    = int(round(barLength * iteration / float(total)))
    percents        = round(100.00 * (iteration / float(total)), decimals)
    bar             = '#' * filledLength + '-' * (barLength - filledLength)
    sys.stdout.write('%s [%s] %s%s %s\r' % (prefix, bar, percents, '%', suffix)),
    sys.stdout.flush()
    if iteration == total:
        print("\n")

if __name__ == '__main__':
    import time

    # parse command line arguments
    parser = argparse.ArgumentParser(description='Parses logfile, prints first line that does not match one of the known regex')
    parser.add_argument('-if', '--in_file', type=str, default="bgl2_clean_workingcopy.log", help='')
    parser.add_argument('-t', '--truncate', type=bool, default=False, help='')
    parser.add_argument('-pd', '--print_duplicates', type=bool, default=False, help='')
    parser.add_argument('-c', '--clean', type=bool, default=False, help='' )
    parser.add_argument("-ds","--dataset_statistics", type=bool, default=False, help="" )
    parser.add_argument("-ss","--show_sorted", type=bool, default=False, help="")
    args = parser.parse_args()
    total_lines = 4747954.0
    one_percent_of_lines = int(total_lines/100)

    if args.clean and False:
        of = open("bgl2_clean.log", "w")
        with open("bgl2.log","r") as logs:

            for i,log_line in enumerate(logs):
                split_line = log_line.split(" ")
                split_line[1] = "TIME_STAMP"
                split_line[2] = "SHORT_DATE"
                if split_line[3]=="NULL":
                    node_id = "NULL"
                elif split_line[3]=="UNKNOWN_LOCATION":
                    node_id = "UNKNOWN_LOCATION"
                elif re.search(r"R\d{2}-M\d-N\w-\w:J\d{2}-U\d{2}",split_line[3]):
                    node_id = "NODE_ID_01"
                elif re.search(r"R\d{2}-M\d-L\d-U\d{2}-\w",split_line[3]):
                    node_id = "NODE_ID_02"
                elif re.search(r"R\d{2}-M\d-?[NL]?\w?",split_line[3]):
                    node_id = "NODE_ID_03"
                else:
                    node_id = split_line[3]

                if split_line[3]==split_line[5]:
                    split_line[3]=node_id
                    split_line[5]=node_id

                split_line[4]="DATE_TIME"

                if i % one_percent_of_lines ==0 : print("%i lines processed, %.2f done "%(i,100*i / total_lines ))
                of.write(" ".join(split_line))
        of.close()
    elif args.truncate and False:
        matched_lines = 0
        of = open("bgl2_clean_workingcopy_new.log", "w")
        with open("bgl2.log","r") as logs:
            for i,log_line in enumerate(logs):
                if i % one_percent_of_lines ==0 : print("%i lines processed, %.2f done "%(i,100*i / total_lines ))
                if extract_pattern_id(log_line) == 0:
                    of.write(log_line)
                else:
                    matched_lines+=1
        of.close()
        import os
        os.remove("bgl2_clean_workingcopy.log")
        os.rename("bgl2_clean_workingcopy_new.log","bgl2_clean_workingcopy.log")
        print("{} signatures matched {} lines, {:.3f}% done.".format(len(KNOWN_LOGLINE_PATTERN), matched_lines, 100*matched_lines / total_lines ))
    elif args.print_duplicates and True:
        lines_with_more_signatures = {}
        log_lines_with_no_signatures = []

        with open("bgl2.log","r") as logs:
            total_ops = 4747954 * len(KNOWN_LOGLINE_PATTERN)
            current_op = 0
            for line_id,log_line in enumerate(logs):
                line_signatures=[]
                if line_id==0:
                    s = time.time()
                if line_id==10000:
                    print "Estimated duration: ~ %.2f h"%( (4747954 * (time.time() -s)/10000.0)/3600.0 )
                for pattern_id, pattern in enumerate(KNOWN_LOGLINE_PATTERN):
                    current_op+=1
                    # print_progress(current_op, total_ops, " regex duplication checks finished")
                    matches = re.search(pattern, log_line)
                    if matches:
                        line_signatures.append(pattern_id+1)
                if len(line_signatures)==0:
                    log_lines_with_no_signatures.append(log_line)
                    print("No pattern matched: %s"%log_line)
                if len(line_signatures)>1:
                    lines_with_more_signatures[line_id] = (log_line, line_signatures, [KNOWN_LOGLINE_PATTERN[s-1] for s in line_signatures] )
                    print("More pattern matched: %s"%log_line)

        print(log_lines_with_no_signatures)
        with open("no_signatures.json","w") as f:
            json_string = json.dumps(log_lines_with_no_signatures)
            f.write(json_string)
        print(lines_with_more_signatures)
        with open("more_signatures.json","w") as f:
            json_string = json.dumps(lines_with_more_signatures)
            f.write(json_string)

    elif args.dataset_statistics and True:
        with open("bgl2.log","r") as logs:
            counts = [0]*(len(KNOWN_LOGLINE_PATTERN)+1)
            for i, log_line in enumerate(logs):
                if i%500==0:
                    print_progress(i, total_lines, " counting dataset statistics")
                pid = extract_pattern_id(log_line)
                counts[pid]+=1

            print("Min: %i"%min(counts))
            print("Max: %i"%max(counts))
            print("Lower Quartile %.2f"%np.percentile(counts, 25))
            print("Median: %.2f"%np.median(counts))
            print("Upper Quartile %.2f"%np.percentile(counts, 75))
            print("Std: %0.2f"%np.std(counts))
            with open("counts.json","w") as f:
                json_coutns_str = json.dumps(counts)
                f.write(json_coutns_str)
    elif args.show_sorted:
        for p in sorted([kp.pattern for kp in KNOWN_LOGLINE_PATTERN]):
            print(p)
        print( "Pattern: %i"%len(KNOWN_LOGLINE_PATTERN))
    else:
        s = time.time()
        total_lines = 736.0
        matched_lines = 0
        with open(args.in_file,"r") as logs:
            for line_id, log_line in enumerate(logs):
                print_progress(line_id, total_lines, "Finding non matching signatures...")
                if extract_pattern_id(log_line) == 0:
                    print("{} signatures matched {} lines, {} lines left,  {:.3f}% done.".format(len(KNOWN_LOGLINE_PATTERN), matched_lines, int(total_lines-matched_lines), 100*matched_lines / total_lines ))
                    print("Line that did not match:\n")
                    print(log_line)
                    copy2clip(log_line)
                    break
                else:
                    if line_id % one_percent_of_lines == 0 : print("%i lines processed, %.2f done "%(line_id,100*line_id / total_lines ))
                    matched_lines+=1
        e = time.time()
        print("Took %i seconds."%(e-s))
