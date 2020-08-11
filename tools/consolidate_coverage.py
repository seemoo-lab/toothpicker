#!/usr/bin/env python2

# This script consolidates individual drcov files

import struct
import binascii
from os.path import isfile, join
from os import listdir

def parse_modules(lines, num):
    modules = []
    for i in range(4, num + 4):
        entry = lines[i].split(b", ")
        module = {
            "id": int(entry[0]),
            "base": int(entry[1], 16),
            "end": int(entry[2], 16),
            "entry": int(entry[3], 16),
            "checksum": int(entry[4], 16),
            "timestamp": int(entry[5], 16),
            "path": entry[6]
        }
        modules.append(module)
    return modules

def parse_coverage(cov):
    coverage = []
    for i in range(0, len(cov)-8):
        part = cov[i*8:(i*8)+8]
        if part != b"":
            (base, length, _id) = struct.unpack("IHH", cov[i*8:(i*8)+8])
            coverage.append((base, length, _id))
    return coverage

def parse_unslid_coverage(cov_file):
    with open(cov_file, "rb") as f:
        content = f.read()
        lines = content.split(b"\n")

        mod_line = lines[2]
        num_modules = int(mod_line[len(mod_line)-3:len(mod_line)])

        # modules = parse_modules(lines, num_modules)
        
        # get the binary part of the coverage file
        cov = b"\n".join(lines[num_modules+5:len(lines)])
        coverage = parse_coverage(cov)
        return coverage

def cleanup_cov(cov):
    clean_cov = []
    for subject in cov:
        # only add if its not yet in the cleaned coverage
        new = True
        for e in clean_cov:
            if e[0] == subject[0]:
                new = False
                continue
        if new:
            clean_cov.append(subject)
    return clean_cov

def rebuild_file(f, cov):
    # get first lines from file 
    header = b""
    with open(f, "rb") as f:
        c = f.read()
        l = c.split(b"\n")

        mod_line = l[2]
        num_modules = int(mod_line[len(mod_line)-3:len(mod_line)])

        header = b"\n".join(l[0:num_modules+4])
    
    content = header + b"\nBB Table: " + bytes(str(len(cov)), "utf8") + b" bbs\n"
    
    for c in cov:
        content += struct.pack("IHH", c[0], c[1], c[2])

    with open("all_cov", "wb") as f:
        f.write(content)


def main():
    onlyfiles = [f for f in listdir(".") if isfile(join(".", f))]
    complete_cov = []
    for f in onlyfiles:
        if f == "all_cov":
            continue

        try:
            cov = parse_unslid_coverage(f)
        except Exception as e:
            print(e)
            cov = []
        complete_cov = complete_cov + cov

    cleaned_cov = cleanup_cov(complete_cov)

    rebuild_file(f[0], cleaned_cov)

if __name__ == "__main__":
    main()
