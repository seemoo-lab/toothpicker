#!/usr/bin/env python3
#
# Libradamsa wrapper using ctypes
#

import ctypes

_use_libradamsa = True

# check if libradamsa is here, if not, use radamsa as a subprocess
try:
    libradamsa = ctypes.CDLL("libradamsa.so")

    libradamsa.radamsa_init()
    libradamsa.radamsa.argtypes = (ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int)

    radamsa_buffer = ctypes.create_string_buffer(700)

except OSError as e:
    _use_libradamsa = False

def radamsa_mutate(input, max, seed):
    in_len = len(input)
    out_len = libradamsa.radamsa(ctypes.c_char_p(input), ctypes.c_int(in_len), radamsa_buffer, 
            ctypes.c_int(max), ctypes.c_int(seed))
    return radamsa_buffer, out_len

def use_libradamsa():
    return _use_libradamsa
