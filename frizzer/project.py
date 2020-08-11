# FRIZZER - project.py
#
# 
#
# Author: Dennis Mantz (ERNW GmbH)

import os
import time
import toml

# frizzer modules
import log

CONFIG_TEMPLATE = """
[fuzzer]
log_level       = 3 # debug
debug_mode      = false

[target]
process_name    = "myprocess"
function        = 0x123456
host            = "localhost"
port            = 7777
ssl             = false
remote_frida    = false
recv_timeout    = 0.1
fuzz_in_process = false
modules = [
        "/home/dennis/tools/frida-fuzzer/tests/simple_binary/test",
    ]
"""

# Singleton instance (can be accessed from everywhere)
instance = None

def getInstance():
    global instance
    if instance == None:
        log.warn("Project instance was not yet created!")
    return instance

def loadProject(project_dir):
    global instance
    if instance != None:
        log.warn("Project instance does already exist!")
        return False

    proj = Project(project_dir)
    if not proj.loadProject():
        log.warn("Could not load project")
        return False

    instance = proj
    return True

def createProject(project_dir):
    os.mkdir(project_dir)
    proj = Project(project_dir)
    if not proj.checkAndCreateSubfolders():
        return False
    with open(proj.config_file, "w") as f:
        f.write(CONFIG_TEMPLATE)
    return True


class Project():
    """
    This class holds all project settings and states. It provides functions to 
    parse the project config file and read/write the state file.
    """

    def __init__(self, project_dir):
        self.project_dir       = project_dir

        # Settings from the config file
        self.process_name     = None
        self.target_function  = None
        self.port             = None
        self.host             = None
        self.ssl              = False
        self.remote_frida     = False
        self.recv_timeout     = None
        self.fuzz_in_process  = False
        self.corpus           = None
        self.corpus_dir       = project_dir + "/corpus"
        self.corpus_trash_dir = project_dir + "/corpus_trash"
        self.crash_dir        = project_dir + "/crashes"
        self.coverage_dir     = project_dir + time.strftime("/%Y%m%d_%H%M%S_coverage")
        self.debug_dir        = project_dir + "/debug"
        self.config_file      = project_dir + "/config"
        self.state_file       = project_dir + "/state"
        self.modules          = None
        self.debug_mode       = False
        self.frida_script     = None

        # State
        self.pid               = None
        self.seed              = 0
        self.crashes           = 0
        self.last_new_path     = -1


    def loadProject(self):

        # Load config file
        if not os.path.exists(self.config_file):
            log.warn("Config file %s does not exist!" % self.config_file)
            return False
        proj = toml.loads(open(self.config_file).read())

        log.info("Project: " + repr(proj))

        if "fuzzer" in proj:
            if "log_level" in proj["fuzzer"]:
                log.log_level   = proj["fuzzer"]["log_level"]
            if "debug_mode" in proj["fuzzer"]:
                self.debug_mode = proj["fuzzer"]["debug_mode"]

        if not "target" in proj:
            log.warn("Section 'target' was not found in config file.")
            return False

        target = proj["target"]

        if not "frida_script" in target:
            log.warn("No 'frida_script' in section 'target'.")
            return False
        self.frida_script = target["frida_script"]

        # if "function" in target:
        #     self.target_function = target["function"]
        # else:
        #     log.warn("No 'function' in section 'target'!")
        #     return False

        if "process_name" in target:
            self.process_name = target["process_name"]
        if "host" in target:
            self.host = target["host"]
        if "port" in target:
            self.port = target["port"]
        if "ssl" in target:
            self.ssl = target["ssl"]
        if "remote_frida" in target:
            self.remote_frida = target["remote_frida"]
        if "recv_timeout" in target:
            self.recv_timeout = target["recv_timeout"]
        if "fuzz_in_process" in target:
            self.fuzz_in_process = target["fuzz_in_process"]

        if "modules" in target:
            self.modules = target["modules"]

        # Load state file
        if os.path.exists(self.state_file):
            state = toml.loads(open(self.state_file).read())
            if "seed" in state:
                self.seed = state["seed"]
            if "pid" in state:
                self.pid = state["pid"]
            if "crashes" in state:
                self.crashes = state["crashes"]
            if "last_new_path" in state:
                self.last_new_path = state["last_new_path"]
            log.info("Found old state. Continuing at seed=%d pid=%s" % (self.seed, str(self.pid)))

        return True

    def saveState(self):
        state = {"seed":            self.seed,
                 "pid":             self.pid,
                 "crashes":         self.crashes,
                 "last_new_path":   self.last_new_path}
        open(self.state_file, "w").write(toml.dumps(state))
        return True

    def checkAndCreateSubfolders(self):
        """
        Check whether alls necessary subdirectories exist in the
        project folder. Create them if necessary.
        """
        if not os.path.exists(self.project_dir):
            log.warn("Project directory '%s' does not exist." % self.project_dir)
            return False

        if not os.path.exists(self.debug_dir):
            os.mkdir(self.debug_dir)

        if os.path.exists(self.debug_dir + "/history"):
            log.debug("Deleting old Debug file: " + self.debug_dir + "/history")
            os.remove(self.debug_dir + "/history")

        #if not os.path.exists(self.coverage_dir):
        #    os.mkdir(self.coverage_dir)

        if not os.path.exists(self.crash_dir):
            os.mkdir(self.crash_dir)

        if not os.path.exists(self.corpus_dir):
            os.mkdir(self.corpus_dir)

        if not os.path.exists(self.corpus_trash_dir):
            os.mkdir(self.corpus_trash_dir)

        return True

