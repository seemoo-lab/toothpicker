#!/usr/bin/env python3

import frida
import binascii
import time
import sys
import os
import struct
import random
from datetime import datetime

class ToothFlipper:
    """
    Fuzz regular ACL/SCO/HCI data by changing bytes.
    Standalone - no radamsa etc. required :)

    Arguments: [device id]

    Settings (ACL only, symbols, etc.) to be adjusted in toothflipper.js!
    """

    def __init__(self):
        """
        Fuzzing parameters and setup.
        """

        # Get device by id
        if len(sys.argv) > 1:
            self.device_id = sys.argv[1]
            self.device = frida.get_device(self.device_id)
        # Just take the first USB device otherwise
        else:
            self.device = frida.get_usb_device()

        self.timeout = 120        # timeout in seconds, quit if no message, indicates bluetoothd crash
        self.timer = 0
        self.exit = False         # True once we want to terminate fuzzing
        self.counter = 0          # current input number

        # save data here
        self.dirname = "%s_%s" % (datetime.now().strftime("bt_toothflipper_%Y-%m-%d_%H-%M-%S"), self.device.id)

        self.fuzz_inplace()

    def on_message(self, message, data):
        if data is None:
            #print("Warning: Got empty data!")
            return

        # Got data, reset timer for quitting the fuzzer
        self.timer = 0

        fname = os.path.join(self.dirname, "%08d" % self.counter)
        f = open(fname, "wb")
        f.write(data)
        f.close()
        self.counter += 1

    def fuzz_inplace(self):
        """
        The actual fuzzer. Just loads the script and passes random seeds.

        :return:
        """
        print("Writing fuzzing files to " + self.dirname + "...")
        os.mkdir(self.dirname)

        frida_session = self.device.attach("bluetoothd")
        script = frida_session.create_script(open("toothflipper.js", "r").read())
        script.on("message", self.on_message)
        script.load()

        # Just wait and change seed from time to time
        while True:
            time.sleep(5)
            self.timer += 5
            if self.timer > self.timeout:
                print("Timeout exceeded, quitting!")
                sys.exit(52)

            # Yeah we could also call Math.random in JavaScript, just a demo how to control seeds etc.
            # Requires the v8 engine, I think, and that was disabled in between...
            try:
                script.exports.seed(random.randint(0, 0xffffffff), random.randint(0, 0xffffffff))
            except:
                print("bluetoothd (or Frida) crashed, quitting...")
                print("Check /var/mobile/Library/Logs/CrashReporter")
                sys.exit(0)


# Run the fuzzer
ToothFlipper()
