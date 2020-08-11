#!/usr/bin/env python3
#
# Frida-based fuzzer for blackbox fuzzing of network services.
#
# Author: Dennis Mantz (ERNW GmbH)

import struct

# frizzer modules
import log

class BasicBlock:
    def __init__(self, start, end, module):
        self.start  = start
        self.end    = end
        self.module = module
    def __hash__(self):
        return self.start
    def __eq__(self, other):
        return self.start == other.__hash__()
    def to_drcov(self):
        #  Data structure for the coverage info itself
        # typedef struct _bb_entry_t {
        #     uint   start;      // offset of bb start from the image base
        #     ushort size;
        #     ushort mod_id;
        # } bb_entry_t;
        return struct.pack("IHH", self.start-self.module["base"],
                                  self.end-self.start,
                                  self.module["id"])
    def __str__(self):
        return hex(self.start)

def parse_coverage(coverage, modules):
    """
    Parse the coverage that is returned from frida_script.exports.getcoverage().
    The RPC function returns a list of basic blocks. The basic block
    itself is another list with two entries: start, end.
    Both, start and end, are unicode strings of hex addresses (e.g. u'0x7f5157f71a3f')

    The blocks are filtered: If a block does not belong to any module in <modules>
    it is ignored.
    """
    bbs = set()
    for bb_list in coverage:
        start = int(bb_list[0], 16)
        end   = int(bb_list[1], 16)
        module = None
        for m in modules:
            if start > m["base"] and end < m["end"]:
                module = m
                break
        if module == None:
            #log.debug("Basic block @0x%x does not belong to any module!" % start)
            continue
        bbs.add(BasicBlock(start, end, module))
    return bbs

def create_drcov_header(modules):
    """
    Takes a module dictionary and formats it as a drcov logfile header.
    """

    if modules == None:
        log.warn("create_drcov_header: modules is None!")
        return None

    header = ''
    header += 'DRCOV VERSION: 2\n'
    header += 'DRCOV FLAVOR: frida\n'
    header += 'Module Table: version 2, count %d\n' % len(modules)
    header += 'Columns: id, base, end, entry, checksum, timestamp, path\n'

    entries = []

    for m in modules:
        # drcov: id, base, end, entry, checksum, timestamp, path
        # frida doesnt give us entry, checksum, or timestamp
        #  luckily, I don't think we need them.
        entry = '%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s' % (
            m['id'], m['base'], m['end'], 0, 0, 0, m['path'])

        entries.append(entry)

    header_modules = '\n'.join(entries)

    return header + header_modules + '\n'

def create_drcov_coverage(bbs):
    # take the recv'd basic blocks, finish the header, and append the coverage
    bb_header = 'BB Table: %d bbs\n' % len(bbs)
    data = [bb.to_drcov() for bb in bbs]
    return bb_header.encode('ascii') + b''.join(data)


def write_drcov_file(modules, coverage, filename):
    """
    Write the coverage to a file using the drcov file format.
    """

    header = create_drcov_header(modules)
    body   = create_drcov_coverage(coverage)

    with open(filename, 'wb') as h:
        h.write(header.encode("ascii"))
        h.write(body)
