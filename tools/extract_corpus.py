#!/usr/bin/env python3

# This script can be used to generate/extract a corpus for a specific protocol.
# It stores individual messages in files consecutively named starting with 0.

# usage: ./extract_corpus.py TARGET_FOLDER VERSION [CID]
# A CID can be optionally given to filter for specific protocols. If you wanted to
# generate a GATT corpus, for example, run: 
#           ./extract_corpus.py your_gatt_project/corpus 13.3 0x04
# the script will wait for input and dump any messages that are sent to or received
# from this CID.

import frida
import binascii
import time
import sys
import os
import struct

# uart_write also known as: UART_write
# acl_recv also known as: ACL_receptionHandler
addresses = {
    "13.3": {
        "uart_write": 0x03a64c,
        "acl_recv": 0xcd824,
    },
    "13.5_17F75": {
        "uart_write": 0x6d5f0,
        "acl_recv": 0x1013f8,
    }
}

counter = 0

if len(sys.argv) < 3:
    print("Please supply a directory name as first argument")
    print("Please supply a version as second argument")
    print(f"Available versions are: {', '.join(addresses.keys())}")
    sys.exit(1)

directory = sys.argv[1]

version = sys.argv[2]
if version not in addresses:
    print("Please supply a valid version")
    sys.exit(2)

cid = None
if len(sys.argv) == 4:
    cid = int(sys.argv[3], 16)


def is_correct_channel(data, cid):
    if len(data) < 8:
        return

    packet_cid = data[6:8]
    packet_cid = struct.unpack_from("h", packet_cid)[0]
    return cid == packet_cid


def on_message(message, data):
    global counter

    if cid and not is_correct_channel(data, cid):
        return

    fname = os.path.join(directory, str(counter))
    print("Writing to " + fname)
    print(binascii.hexlify(data))
    f = open(fname, "wb")
    f.write(data)
    f.close()
    counter += 1


frida_session = frida.get_usb_device(1).attach("bluetoothd")
# Signature of recv_acl is: (ulonglong handle, byte len, byte* data)
# so x1 contains the length and x2 contains the data
# thereby we read four bytes more than the pointer is pointing to
# thus we also have to increase the len by four.
# why is this done?
#
# Signature of uart_write is: (byte * buf, uint len) (types may differ)
# so x0 contains the buffer address and x1 the length
# again only some portion is read
# also in this case this all is only done in case x0 hold 0x02?
# again: why is this done?
script = frida_session.create_script(f"\
        var base = Module.getBaseAddress('bluetoothd'); \
        var recv_acl = base.add({addresses[version]['acl_recv']}); \
        Interceptor.attach(recv_acl, function() {{ \
            var x=this.context; \
            send('data', Memory.readByteArray(ptr(x.x2).add(-4), parseInt(x.x1)+4)) \
        }}); \
        \
        var uart_write = base.add({addresses[version]['uart_write']}); \
        Interceptor.attach(uart_write, function() {{ \
            var x=this.context; \
            if (Memory.readS8(x.x0) == 0x02) \
                send('data', Memory.readByteArray(ptr(x.x0).add(1), parseInt(x.x1)-1)) \
        }}); \
    ")

script.on("message", on_message)
script.load()

while True:
    time.sleep(2)
