import sys
import time
import os
import binascii

from pwn import *
from internalblue.ioscore import iOSCore
import internalblue.hci as hci
from random import randrange

from BTConnection import BluetoothConnection
import InternalBlueL2CAP
from OTAFuzzer import OTAFuzzer

class MPFuzzer:
    # MagicPairing Message Type / Opcodes
    MP_MESSAGE_TYPE_HINT = 1
    MP_MESSAGE_TYPE_RATCHETAESSIV = 2
    MP_MESSAGE_TYPE_AESSIV = 3
    MP_MESSAGE_TYPE_RATCHET = 4
    MP_MESSAGE_TYPE_PING = 0xf0
    MP_MESSAGE_TYPE_STATUS = 0xff
    # MagicPairing Key Type Fields
    MP_KEY_TYPE_HINT = 0x10
    MP_KEY_TYPE_NONCE = 0x20
    MP_KEY_TYPE_UNKNOWN = 0x40
    MP_KEY_TYPE_AESSIV = 0x80
    MP_KEY_TYPE_RATCHET = 0x100
    
    def __init__(self, target):
        # set up internalblue, adapt if you need a different core or device
        self.internalblue = iOSCore(log_level="DEBUG")
        devices = self.internalblue.device_list()
        i = options("Please specify device: ", [d[2] for d in devices], 0)
        self.internalblue.interface = self.internalblue.device_list()[i][1]
        if not self.internalblue.connect():
            log.critical("No connection to internalblue device")
            sys.exit(-1)

        # for MP it might make sense to change this to a known device address
        # as unknown addresses cause the receiving iPhone to crash constantly
        # as long as Apple does not fix these NULL pointer derefs
        # self.internalblue.sendHciCommand(0xfc01, bytes.fromhex("cafebabe1337"))

        # set up BT connection to the target
        self.connection = BluetoothConnection(self.internalblue, target, reconnect=0)
        self.connection.connect()

        self.fuzzer = None
        self.connection.connection_callback = self.init_fuzzer()
    
    def init_fuzzer(self):
        self.fuzzer = OTAFuzzer(connection=self.connection, prepare_fn=self.prepare, 
                                    reception_handler_fn=self.reception_handler, 
                                    CID=0x30, generator_fn=self.generator)

    def fuzz(self):
        while self.fuzzer == None:
            log.info("Waiting for successful connection before starting to fuzz")
            time.sleep(1)
        self.fuzzer.fuzz()

    def is_finished(self):
        return self.fuzzer.finished

    def reception_handler(self, data):
        log.info("MP Data: " + binascii.hexlify(data).decode("utf-8"))

    def prepare(self):
        # not really required but seems to increase the L2CAP MTU on the receiver side which
        # might be an issue for longer key-type MP messages
        self.internalblue.sendH4(0x02, bytes.fromhex("0B200A00060001000A0B02000200"))
        self.internalblue.sendH4(0x02, bytes.fromhex("0B2010000C0001000B0D08000200000080020000"))
        self.internalblue.sendH4(0x02, bytes.fromhex("0B200A00060001000A0C02000300"))
        self.internalblue.sendH4(0x02, 
                bytes.fromhex("0B201400100001000B1B0C00030000001000000000000100"))
        time.sleep(0.5)

    def generator(self):
        # randomly decide what message type should be sent
        mpType = random.choice([0x01, 0x02, 0x04, 0x0b, 0xf0, 0xff])
        data = self.create_MP_message_with_random_quality(mpType)
        log.info("Fuzzing(c=" + chr(mpType) +"):" + binascii.hexlify(data).decode("utf-8"))
        if len(data) > 1026:
            log.info("Payload too long, iPhone will reject, cutting it...")
            data = data[:1026]
        return data

    def create_key_with_type(self, ktype, length=0, length_field=0):
        # type, lenght, value
        buf = p16(ktype) + p16(length_field)
        buf += os.urandom(length)
        return buf 

    def create_MP_message_with_random_quality(self, mpType):
        # there are five choices we can make regarding the quality of the packet we generate
        # 1. the packet contains completely valid data (except for key material and encrypted 
        #       content)
        # 2. the packet contains malformed length fields
        # 3. the packet contains data fields with wrong lengts (this is not the same as 2 
        #       as macOS sometimes assumes the lenght of a key)
        # 4. the packet contains different key material than the type expects
        # 5. the packet contains more/less keys than specified
        quality = random.choice([1, 2, 3, 4, 5])
        buf = b""
        if quality <= 3:
            if mpType == self.MP_MESSAGE_TYPE_HINT:
                # type hint, version 01
                buf += b'\x01\x01'
                log.info(chr(quality))
                # three key entries for valid hint messages
                buf += b'\x03'
                if quality == 1: 
                    _hint_len_field = _hint_len = 0x10
                    _nonce_len_field = _nonce_len = 0x10
                    _ratchet_len_field = _ratchet_len = 0x04
                elif quality == 2:
                    _hint_len = 0x10
                    _nonce_len = 0x10
                    _ratchet_len = 0x04
                    _hint_len_field = randrange(0x00, 0xffff)
                    _nonce_len_field = randrange(0x00, 0xffff)
                    _ratchet_len_field = randrange(0x00, 0xffff)
                else:
                    _hint_len = randrange(0x00, 0xff, 2)
                    _nonce_len = randrange(0x00, 0xff, 2)
                    _ratchet_len = randrange(0x00, 0xff, 2)
                    _hint_len_field = 0x10
                    _nonce_len_field = 0x10
                    _ratchet_len_field = 0x04
                
                buf += self.create_key_with_type(self.MP_KEY_TYPE_HINT, length=_hint_len,
                        length_field=_hint_len_field)
                buf += self.create_key_with_type(self.MP_KEY_TYPE_NONCE, length=_nonce_len,
                        length_field=_nonce_len_field)
                buf += self.create_key_with_type(self.MP_KEY_TYPE_RATCHET, length=_ratchet_len, 
                        length_field=_ratchet_len_field)

            elif mpType == self.MP_MESSAGE_TYPE_RATCHETAESSIV:
                # type RatchetAESSIV version 1
                buf = b"\x02\x01"
                # there are two keys in a valid Ratchet AESSIV message
                buf += b"\x02"
                if quality == 1:
                    _raes_len_field = _raes_len = 0x36
                    _ratchet_len_field = _ratchet_len = 0x04
                elif quality == 2:
                    _raes_len = 0x36
                    _ratchet_len = 0x04
                    _raes_len_field = randrange(0x00, 0xffff)
                    _ratchet_len_field = randrange(0x00, 0xffff)
                elif quality == 3:
                    _raes_len = randrange(0x00, 0xff, 2)
                    _ratchet_len = randrange(0x00, 0xff, 2)
                    _raes_len_field = 0x36
                    _ratchet_len_field = 0x04
                
                buf += self.create_key_with_type(self.MP_KEY_TYPE_AESSIV, 
                            length=_raes_len, length_field=_raes_len_field)
                buf += self.create_key_with_type(self.MP_KEY_TYPE_RATCHET, 
                            length=_ratchet_len, length_field=_ratchet_len_field)
            
            elif mpType == self.MP_MESSAGE_TYPE_AESSIV:
                # type AESSIV version 1
                buf = b"\x03\x01"
                # there is only one key in a valid AESSIV message
                buf += b"\x01"
                if quality == 1:
                    _aes_len_field = _aes_len = 0x50
                elif quality == 2:
                    _aes_len = 0x50
                    _aes_len_field = randrange(0x00, 0xffff)
                elif quality == 3:
                    _aes_len = randrange(0x00, 0xff, 2)
                    _aes_len_field = 0x50

                buf += self.create_key_with_type(self.MP_KEY_TYPE_AESSIV, length=_aes_len,
                        length_field=_aes_len_field)

            elif mpType == self.MP_MESSAGE_TYPE_RATCHET or mpType == self.MP_MESSAGE_TYPE_HINT:
                # type ... version 1
                buf = bytes([mpType])
                buf += b"\x01"
                # the ratchet message is not really specified and the hint message does
                # not really have any content. So just generate anything...
                buf += os.urandom(19)

            elif mpType == self.MP_MESSAGE_TYPE_STATUS:
                # type status version 1
                buf = b"\xff\x01"
                # status does not have a lenght field but we can send valid data or data 
                # that is too long
                if quality == 1 or quality == 2:
                    buf += os.urandom(1)
                else:
                    buf += os.urandom(randrange(0x00, 0xff))
            
            elif mpType == 0x0b:
                buf = b"\x0b\x01"
                buf += os.urandom(randrange(0, 12))

        # quality type 4 and 5
        else:
            # how many keys do we want to generate?
            b_num_keys = num_keys = randrange(0x00, 0xf)
            if quality == 5:
                # specify a wrong number of key entries
                b_num_keys = randrange(0x00, 0xf0)
            
            keybuf = b""
            for i in range(0, num_keys):
                # which key do we want to generate
                keytype = random.choice([0x10, 0x20, 0x40, 0x80, 0x100])
                key_len = randrange(0x00, 0x18f)
                key_len_field = randrange(0x00, 0xffff)
                k = self.create_key_with_type(keytype, length=key_len, 
                        length_field=key_len_field)
                keybuf += k

            buf += bytes([mpType, 0x01])
            buf += p8(b_num_keys)
            buf += keybuf
        
        return buf

def main():
    if len(sys.argv) != 2:
        print("Usage: " + sys.argv[0] + " [TARGET-BDADDR]")
        exit(-1)

    # replace colons so that BT addresse copied from tool output can be used
    bd_addr = bytes.fromhex(sys.argv[1].replace(":", ""))

    mpFuzzer = MPFuzzer(bd_addr)

    mpFuzzer.fuzz()

    while mpFuzzer.is_finished() == False:
        time.sleep(1)

if __name__ == "__main__":
        main()

