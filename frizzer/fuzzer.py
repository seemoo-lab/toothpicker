#!/usr/bin/env python3
#
# Frida-based fuzzer for blackbox fuzzing of network services.
#
# Original Authors: Dennis Mantz (ERNW GmbH)
#                   Birk Kauer   (ERNW GmbH)
# see github.com/demantz/frizzer
#
# ToothPicker adaptions:    Dennis Heinze
#                           Jiska Classen
#                           Kristoffer Schneider
#

from subprocess import check_output
import argparse
import frida
import socket
import ssl
import time
import shutil
import sys
import os
import binascii
import threading

# frizzer modules:
import log
import project
from coverage import parse_coverage, write_drcov_file
from radamsa import radamsa_mutate, use_libradamsa


#
# FridaFuzzer Class
#

ms_time_now = lambda: int(round(time.time() * 10000))

class FridaFuzzer:
    """
    This class operates the fuzzing process.
    """

    def __init__(self, project):
        self.project = project
        self.corpus = None
        self.corpus_cache = {}
        self.frida_session = None
        self.frida_script = None
        self.modules = None
        self.watched_modules = None
        self.accumulated_coverage = set()
        self.total_executions = 0
        self.start_time = None
        self.is_ready = False
        self.fuzz_count = 0
        self.previous_payload = None
        self._frida_script_obj = None

        if not os.path.exists(project.coverage_dir):
            os.mkdir(project.coverage_dir)

    def get_module_map(self):
        if self.frida_script is None:
            log.warn("getModuleMap: self.frida_script is None!")
            return None

        try:
            module_map = self.frida_script.get_maps()
        except frida.core.RPCException as e:
            log.info("RPCException: " + repr(e))
            return None

        self.modules = []
        for image in module_map:
            idx = image['id']
            path = image['path']
            base = int(image['base'], 0)
            end = int(image['end'], 0)
            size = image['size']

            m = {
                'id': idx,
                'path': path,
                'base': base,
                'end': end,
                'range': range(base, end),
                'size': size}

            self.modules.append(m)
        return self.modules

    def create_module_filter_list(self):
        """
        Creates the list of modules in which coverage information
        should be collected. This list is created by querying frida
        for the loaded modules and comparing them to the modules
        the user selected in the project settings.

        Must be called after frida was attached to the target and
        before any coverage is collected.
        """

        if self.modules is None:
            log.warn("filterModules: self.modules is None!")
            return False

        self.watched_modules = []
        for module in self.modules:
            if module["path"] in self.project.modules:
                self.watched_modules.append(module)

        if len(self.watched_modules) == 0:
            paths = "\n".join([m["path"] for m in self.modules])
            log.warn("filterModules: No module was selected! Possible choices:\n" + paths)
            return False
        else:
            paths = "\n".join([m["path"] for m in self.watched_modules])
            log.info("Filter coverage to only include the following modules:\n" + paths)
            return True

    def on_message(self, message, data):
        if 'payload' in message.keys() and str(message['payload']) == "finished":
            pass
        elif 'payload' in message.keys() and str(message['payload']) == 'ready':
            # wait for the script to tell us that we can start fuzzing
            self.is_ready = True
        if "payload" in message:
            log.info("on_message: " + str(message['payload']))
        log.info("on_message (msg): " + str(message))
        log.info("on_message (data): " + str(data))

    def load_script(self):
        script_file = os.path.join(self.project.frida_script)
        log.info("Loading script: %s" % script_file)
        script_code = open(script_file, "r").read()
        script = self.frida_session.create_script(script_code, runtime='v8')

        script.on('message', self.on_message)
        script.load()
        self._frida_script_obj = script
        self.frida_script = script.exports
        self.frida_script.prepare()
        return script

    def send_fuzz_payload_in_process(self, payload):
        """
        Send fuzzing payload to target process by invoking the target function
        directly in frida
        """

        # Call function under fuzz:
        encoded = payload.hex()
        cov = None
        try:
            cov = self.frida_script.fuzz_internal(encoded)
        except frida.core.RPCException as e:
            log.info("RPCException: " + repr(e))
            truncated_payload = str(binascii.hexlify(payload))[:25]
            log.warn("had payload: " + truncated_payload + "[...]")

            if original_corpus_file not in self.corpus_blacklist:
                log.info("adding %s to corpus blacklist due to crash." % original_corpus_file) 
                self.corpus_blacklist.append(original_corpus_file)
            # # remove responsible corpus file from corpus list (but not from disk)
            # if original_corpus_file and corpus:
            #     # need to check if we already removed this, other mutations from this corpus
            #     # might still arrive here
            #     if original_corpus_file in corpus:
            #         log.info("Removing %s from corpus due to crash." % original_corpus_file)
            #         corpus.remove(original_corpus_file)

            # save crash file
            crash_file = self.project.crash_dir + time.strftime("/%Y%m%d_%H%M%S_crash")
            with open(crash_file + "_" + str(self.project.pid), "wb") as f:
                f.write(bytes(str(self.project.seed) + "\n", "utf8"))
                f.write(bytes(repr(e), "utf8") + bytes('\n', "utf8"))
                f.write(binascii.hexlify(payload))
            log.info("Payload is written to " + crash_file)
            self.project.crashes += 1

    def get_coverage_of_payload(self, payload, timeout=0.1, retry=5):
        """
        Sends of the payload and checks the returned coverage.

        Important:
            Frida appears to have a bug sometimes in collecting traces with the stalker.. no idea how to fix this yet..
            hence we do a retry. This can however screw up the replay functionality and should be fixed in the future.

        Arguments:
            payload {[type]} -- [description]

        Keyword Arguments:
            timeout {float} -- [description] (default: {0.1})
            retry {int} -- [description] (default: {5})

        Returns:
            [type] -- [description]
        """
        cnt = 0
        cov = None
        while cnt <= retry:
            try:
                self.fuzz_count += 1
                start = ms_time_now()
                cov = self.send_fuzz_payload_in_process(payload, original_corpus_file, corpus)
                end = ms_time_now()
                self.send_fuzz_payload_in_process_time += end - start

                start = time.time()
                # cov = None
                _start = ms_time_now()
                while (cov == None or len(cov) == 0) and (time.time()-start) < timeout:
                    cov = self.frida_script.get_coverage()
                _end = ms_time_now()
                self.fuzz_get_coverage_time += _end - _start

                if cov is not None and len(cov) > 0:
                    break

                cnt += 1

                if cov is None or len(cov) == 0:
                    log.info("getCoverageOfPayload: got nothing!")
            except frida.InvalidOperationError as e:
                log.warn("Error communicating with the frida script: %s" % str(e))
                log.warn("I probably crashed with the following payload: ")
                log.warn(str(binascii.hexlify(self.previous_payload)))
                self.detach()
                time.sleep(30)
                self.attach()
                self.frida_script.prepare()
                while not self.frida_script.is_ready():
                    time.sleep(0.2)
                self.frida_script.post_prepare()

        self.previous_payload = payload
        if cov is None:
            cov = []
        bbcov = parse_coverage(cov, self.watched_modules)
        return bbcov

    def build_corpus(self):
        log.info("Initializing Corpus...")

        # Resetting Corpus to avoid at restart to have with ASLR more blocks than needed
        self.accumulated_coverage = set()

        corpus = [self.project.corpus_dir + "/" + x for x in os.listdir(self.project.corpus_dir)]
        corpus.sort()

        for c in self.corpus_blacklist:
            if c in corpus:
                corpus.remove(c)

        if len(corpus) == 0:
            log.warn("Corpus is empty, please add files/directories with 'add'")
            return False

        for infile in corpus:
            fuzz_pkt = open(infile, "rb").read()
            coverage_last = None
            for i in range(5):
                t = time.strftime("%Y-%m-%d %H:%M:%S")
                log.update(t + " [iteration=%d] %s" % (i, infile))

                # send packet to target
                coverage = self.get_coverage_of_payload(fuzz_pkt, infile, corpus)
                if coverage is None or len(coverage) == 0:
                    log.warn(f"No coverage was returned! you might want to delete {infile} from corpus if it happens "
                             f"more often")

                # log.info("Iteration=%d  covlen=%d file=%s" % (i, len(coverage), infile))

                if coverage_last is not None and coverage_last != coverage:
                    log.warn(t + " [iteration=%d] Inconsistent coverage for %s!" % (i, infile))
                    # log.info("diff a-b:" + " ".join([str(x) for x in coverage_last.difference(coverage)]))
                    # log.info("diff b-a:" + " ".join([str(x) for x in coverage.difference(coverage_last)]))

                coverage_last = coverage
                # Accumulate coverage:
                self.accumulated_coverage = self.accumulated_coverage.union(coverage_last)

            write_drcov_file(self.modules, coverage_last,
                             self.project.coverage_dir + "/" + infile.split("/")[-1])

        log.finish_update("Using %d input files which cover a total of %d basic blocks!" % (
            len(corpus), len(self.accumulated_coverage)))
        self.corpus = corpus
        return True

    def do_iteration(self, seed=None, corpus=None):
        if seed is None:
            seed = self.project.seed
        if corpus is None:
            corpus = self.corpus

        start_time = time.time()
        for pkt_file in corpus:
            # log.update("[seed=%d] " % seed + time.strftime("%Y-%m-%d %H:%M:%S") + " %s" % pkt_file)
            #log.info(time.strftime("%Y-%m-%d %H:%M:%S") + " %s" % pkt_file)
            start = ms_time_now()
            if not use_libradamsa():
                fuzz_pkt = check_output(["radamsa", "-s", str(seed), pkt_file])
                if len(fuzz_pkt) > 672:
                    fuzz_pkt = fuzz_pkt[:672]
            else:
                if pkt_file not in self.corpus_cache:
                    log.finish_update("%s not in cache" % pkt_file)
                    input_pkt_data = b''
                    with open(pkt_file, 'rb') as input_pkt_file:
                        self.corpus_cache[pkt_file] = input_pkt_file.read()

                (fuzz_pkt, fuzz_pkt_len) = radamsa_mutate(self.corpus_cache[pkt_file], 672, seed)
                fuzz_pkt = fuzz_pkt[:fuzz_pkt_len]
            end = ms_time_now()
            self.mutation_time += end - start

            # do any protocol or target specific transformations on the fuzzing payload
            # if the user did not specify this function it will just return the untouched
            # payload
            try:
                start = ms_time_now()
                fuzz_bin = self.frida_script.process_payload(fuzz_pkt.hex())
                fuzz_pkt = binascii.unhexlify(fuzz_bin)
                end = ms_time_now()
                self.process_payload_time += end - start 
            except:
                pass

            # Writing History file for replaying
            open(self.project.project_dir + "/frida_fuzzer.history", "a").write(str(pkt_file) + "|" + str(seed) + "\n")

            try:
                start = ms_time_now()
                coverage = self.get_coverage_of_payload(fuzz_pkt, pkt_file, corpus)
                end = ms_time_now()
                self.get_coverage_of_payload_time += end - start
            except (frida.TransportError, frida.InvalidOperationError) as e:
                log.warn("doIteration: Got a frida error: " + str(e))
                truncated_payload = str(binascii.hexlify(fuzz_pkt))[:25]
                log.warn("had payload: " + truncated_payload + " [...]")
                log.info("Current iteration: " + time.strftime("%Y-%m-%d %H:%M:%S") +
                         " [seed=%d] [file=%s]" % (seed, pkt_file))
                crash_file = self.project.crash_dir + time.strftime("/%Y%m%d_%H%M%S_crash")
                with open(crash_file + "_" + str(self.project.pid), "wb") as f:
                    f.write(fuzz_pkt)
                log.info("Payload is written to " + crash_file)
                self.project.crashes += 1
                return False

            if coverage is None:
                log.warn("No coverage was generated for [%d] %s!" % (seed, pkt_file))
                continue

            if not coverage.issubset(self.accumulated_coverage):
                # New basic blocks covered!
                log.info("Found new path: [%d] %s" % (seed, pkt_file))
                newfile = open(self.project.corpus_dir + "/" + str(seed) + "_" + pkt_file.split("/")[-1], "wb")
                newfile.write(fuzz_pkt)
                newfile.close()

                cov_file = self.project.coverage_dir + "/" + pkt_file.split("/")[-1]
                write_drcov_file(self.modules, coverage, cov_file)
                write_drcov_file(self.modules, coverage.difference(self.accumulated_coverage),
                                 cov_file + "_diff")

                self.project.last_new_path = seed
                self.accumulated_coverage = self.accumulated_coverage.union(coverage)

            self.total_executions += 1

        end_time = time.time()
        speed = len(corpus) / (end_time-start_time)
        avg_speed = self.total_executions / (end_time-self.start_time)
        self.current_speed_avg = avg_speed

        log.finish_update("[seed=%d] speed=[%3d exec/sec (avg: %d)] coverage=[%d bblocks] corpus=[%d files] "
                          "last new path: [%d] crashes: [%d]" % (
                              seed, speed, avg_speed, len(self.accumulated_coverage), len(corpus),
                              self.project.last_new_path, self.project.crashes))
        return True

    def do_replay(self):
        """
        This function replays the last Session. This function will later implement also probes to test when the process
        is crashing
        """
        log.info("Starting the full Replay")
        with open(self.project.project_dir + "/frida_fuzzer.history") as fp:
            for line in fp:
                pkt_file, seed = line.split("|")
                try:
                    # if libradamsa is not used, we call it as a subprocess and won't cache file contents
                    if not use_libradamsa():
                        fuzz_pkt = check_output(["radamsa", "-s", str(seed.strip()), pkt_file])
                        # kind of arbitrary size limit, probably change this if you're fuzzing something
                        # else than Bluetooth protocols
                        if len(fuzz_pkt) > 672:
                            fuzz_pkt = fuzz_pkt[:672]
                    else:
                        if pkt_file not in self.corpus_cache:
                            input_pkt_data = b''
                            with open(pkt_file, 'rb') as input_pkt_file:
                                self.corpus_cache[pkt_file] = input_pkt_file.read()

                        fuzz_pkt = radamsa_mutate(self.corpus_cache[pkt_file], 672, int(seed))

                    # do any protocol or target specific transformations on the fuzzing payload
                    # if the user did not specify this function it will just return the untouched
                    # payload
                    fuzz_pkt = binascii.unhexlify(self.frida_script.process_payload(fuzz_pkt.hex()))

                    if self.project.debug:
                        open(self.project.debug_dir + "/history", "a").write("file: {} seed: {} \n{}\n".format(
                            pkt_file,
                            seed,
                            fuzz_pkt,
                            ))
                    coverage = self.get_coverage_of_payload(fuzz_pkt, pkt_file, None)
                    log.info("Current iteration: " + time.strftime("%Y-%m-%d %H:%M:%S") +
                             " [seed=%d] [file=%s]" % (int(seed.strip()), pkt_file))
                except (frida.TransportError, frida.InvalidOperationError) as e:
                    log.success("doReplay: Got a frida error: " + str(e))
                    log.success("Current iteration: " + time.strftime("%Y-%m-%d %H:%M:%S") +
                                " [seed=%d] [file=%s]" % (int(seed.strip()), pkt_file))
                    log.success("Server Crashed! Lets narrow it down")
                    # crash_file = self.crash_dir + time.strftime("/%Y%m%d_%H%M%S_crash")
                    # with open(crash_file, "wb") as f:
                    #    f.write(fuzz_pkt)
                    # log.info("Payload is written to " + crash_file)
                    return False

                if coverage is None:
                    log.warn("No coverage was generated for [%d] %s!" % (seed, pkt_file))
        log.info("Sending Empty Package to verify the crashing server")
        try:
            coverage = self.get_coverage_of_payload(b'FOOBAR')
        except (frida.TransportError, frida.InvalidOperationError) as e:
            log.success("Server Crashed! Lets narrow it down")
            # TODO
            # Rabbit Mode here

        log.warn("History did not crash the Server! Might be due to some race conditions.")
        return False

    def metric_timer_fn(self):
        metric_filename = "metrics-%d-%d" % (int(self.start_time), self.initial_seed)
        # only start to do metrics if we have executions
        if self.total_executions > 0:
            # we open and close the file on each timer event to prevent any data loss
            # on crashes
            self.metric_file = open(metric_filename, "a")

            # metric file format:
            # timestamp, BBs, crashes, current_seed, current_speed_avg, mutation_avg, process_payload_avg, 
            # get_coverage_of_payload_avg, send_fuzz_payload_in_process_avg, fuzz_get_coverage_time 
            mutation_avg = self.mutation_time / self.total_executions
            process_payload_avg = self.process_payload_time / self.total_executions
            get_coverage_of_payload_avg = self.get_coverage_of_payload_time / self.total_executions
            send_fuzz_payload_in_process_avg = self.send_fuzz_payload_in_process_time / self.total_executions
            fuzz_get_coverage_time = self.fuzz_get_coverage_time / self.total_executions

            self.metric_file.write("%d, %d, %d, %d, %d, %d, %d, %d, %d, %d\n" % (
                int(time.time()), 
                len(self.accumulated_coverage),
                self.project.crashes,
                self.project.seed,
                self.current_speed_avg,
                mutation_avg, 
                process_payload_avg, 
                get_coverage_of_payload_avg, 
                send_fuzz_payload_in_process_avg,
                fuzz_get_coverage_time))
            
            self.metric_file.close()

        t = threading.Timer(1.0, self.metric_timer_fn)
        t.start()

    def fuzzerLoop(self):
        self.get_module_map()
        try:
            self.start_time = time.time()
            self.initial_seed = self.project.seed
            self.total_executions = 0
            # start timer for metric measurements
            self.metric_timer_fn()
            metric_filename = "metrics-%d-%d" % (int(self.start_time), self.initial_seed)
            if not os.path.isfile(metric_filename):
                f = open(metric_filename, "a")
                f.write("initial seed: %d, start time: %d\n" % (int(self.start_time), self.initial_seed))
                f.write("timestamp, BBs, crashes, cur_seed, speed_avg, mutation, process_payload, get_coverage_of_payload, send_fuzz_payload_in_process, fuzz_get_coverage\n")
                f.close()

            while True:
                if not self.do_iteration():
                    log.info("stopping fuzzer loop")
                    return False
                self.corpus = [self.project.corpus_dir + "/" + f for f in os.listdir(self.project.corpus_dir)]
                for c in self.corpus_blacklist:
                    if c in self.corpus:
                        self.corpus.remove(c)
                self.corpus.sort()
                self.project.seed += 1
                self.project.saveState()
        except KeyboardInterrupt:
            log.info("Interrupted by user..")

    def attach(self):
        # if self.project.pid != None:
        #     target_process = self.project.pid
        if self.project.process_name is not None:
            target_process = self.project.process_name
        else:
            log.warn("No process specified with 'process_name' or 'pid'!")
            return False

        if self.project.remote_frida:
            self.frida_session = frida.get_usb_device(1).attach(target_process)
        else:
            self.frida_session = frida.attach(target_process)
        self.load_script()
        pid = self.frida_script.get_pid()
        log.info("Attached to pid %d!" % pid)
        self.project.pid = pid

        # Query the loaded modules from the target
        self.get_module_map()

        # ... and create the module filter list
        self.create_module_filter_list()
        return True

    def detach(self):
        try:
            self._frida_script_obj.unload()
        except frida.InvalidOperationError as e:
            log.warn("Could not unload frida script: " + str(e))

        self.frida_session.detach()


###
### frizzer sub functions
### (init, add, fuzz, ...)
##

def init(args):
    if os.path.exists(args.project):
        log.warn("Project '%s' already exists!" % args.project)
        return
    log.info("Creating project '%s'!" % args.project)
    if not project.createProject(args.project):
        log.warn("Could not create project!")


def add(args):
    infiles = []
    for path in args.input:
        if not os.path.exists(path):
            log.warn("File or directory '%s' does not exist!" % path)
            return
        if os.path.isdir(path):
            infiles.extend([path + "/" + x for x in os.listdir(path)])
        else:
            infiles.append(path)

    corpus_dir = project.getInstance().corpus_dir
    for inFile in infiles:
        if not os.path.exists(corpus_dir + "/" + inFile.split("/")[-1]):
            log.info("Copying '%s' to corpus directory: " % inFile)
            shutil.copy2(inFile, corpus_dir)


def fuzz(args, fuzzer):

    # wait until our fuzzing harness is ready for receiving input data
    while not fuzzer.frida_script.is_ready():
        time.sleep(0.2)

    # execute any preparation steps after the harness is ready
    fuzzer.frida_script.post_prepare()

    if fuzzer.build_corpus():
        log.debug("Corpus: " + str(fuzzer.corpus))
    fuzzer.fuzzer_loop()

###
### Argument Parsing
###

def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    # Add subcommands
    parser_init     = subparsers.add_parser('init')
    parser_add      = subparsers.add_parser('add')
    parser_fuzz     = subparsers.add_parser('fuzz')
    parser_replay   = subparsers.add_parser('replay')

    # Assign functions to subcommands
    parser_init.set_defaults(func=init)
    parser_add.set_defaults(func=add)
    parser_fuzz.set_defaults(func=fuzz)

    # Add general options
    for p in [parser_init, parser_add, parser_fuzz, parser_replay]:
        p.add_argument("--verbose", "-v", action='store_true', help="Change log level to 'debug'")
        p.add_argument("--debug", action='store_true', help="Verbose Debugging in a file (every Request)")

    # Add subcommand specific parser options:
    for p in [parser_add, parser_fuzz, parser_replay]:
        p.add_argument("--project", "-p", help="Project directory.")

    for p in [parser_fuzz, parser_replay]:
        p.add_argument("--pid", help="Process ID or name of target program")
        p.add_argument("--seed", "-s", help="Seed for radamsa", type=int)
        p.add_argument("--function", "-f", help="Function to fuzz and over which the coverage is calculated")

    parser_init.add_argument("project", help="Project name / directory which will be created)")
    parser_add.add_argument("input", nargs="*", help="Input files and directories that will be added to the corpus")

    # Parse arguments
    args = parser.parse_args()

    if args.verbose:
        log.log_level = 3
    if args.project is None:
        log.warn("Please specify a project directory name with --project/-p")
        sys.exit(-1)

    return args


def main():
    args = parse_args()

    if args.command != "init":
        # Load project
        if not project.loadProject(args.project):
            log.warn("Error: Could not load project '%s'!" % args.project)
            return
        if args.seed:
            project.getInstance().seed = args.seed

    if args.command in ["fuzz", "replay"]:
        # Create Fuzzer and attach to target
        fuzzer = FridaFuzzer(project.getInstance())
        if not fuzzer.attach():
            return

        # Invoke subcommand function with instantiated fuzzer
        args.func(args, fuzzer)

        log.info("Detach Fuzzer ...")
        fuzzer.detach()

    else:
        # Invoke subcommand function
        args.func(args)

    log.info("Done")
    return


if __name__ == "__main__":
    main()
