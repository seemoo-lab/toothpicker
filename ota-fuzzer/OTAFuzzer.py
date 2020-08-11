import sys
from pwn import *

from BTConnection import BluetoothConnection
import InternalBlueL2CAP

class OTAFuzzer:

    def __init__(self, connection=None, prepare_fn=None, reception_handler_fn=None, 
                    CID=None, generator_fn=None):
        self.l2cap = InternalBlueL2CAP.L2CAPManager(connection)

        if generator_fn != None:
            self.generator_fn= generator_fn
        else:
            log.error("Cannot create an OTA Fuzzer instance without an generator function")
            sys.exit(-1)

        if CID == None:
            log.error("Cannot create an OTA Fuzzer instance without knowning the targeted CID")
            sys.exit(-1)
        self.CID = CID

        if reception_handler_fn:
            self.l2cap.registerCIDHandler(reception_handler_fn, CID)

        if prepare_fn:
            prepare_fn()

        self.finished = False

    def fuzz(self):
        while not self.finished:
            data = self.generator_fn()
            self.l2cap.sendData(data, self.CID)
            time.sleep(0.5)
