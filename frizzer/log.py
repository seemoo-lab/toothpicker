# This is a temporary replacement for pwntools' log command
# TODO: Add sophisticated logging + nice ui output etc.

import sys

# colors:
COLOR_NC = '\033[0m'  # No Color
WHITE = '\033[37m'
BLACK = '\033[30m'
BLUE = '\033[34m'
GREEN = '\033[32m'
CYAN = '\033[36m'
RED = '\033[31m'
PURPLE = '\033[35m'
BROWN = '\033[33m'
YELLOW = '\033[33m'
GRAY = '\033[30m'

update_ongoing = False

# debug = 3   info = 2   warn = 1
log_level = 2


def add_color(msg, color):
    return color + msg + COLOR_NC


def writeLine(msg):
    global update_ongoing
    if update_ongoing:
        sys.stdout.write("\n")
    sys.stdout.write(msg + "\n")
    update_ongoing = False


def update(msg):
    global update_ongoing, log_level
    if log_level >= 2:
        update_ongoing = True
        sys.stdout.write("\r[" + add_color("*", YELLOW) + "] " + msg)


def finish_update(msg):
    global update_ongoing, log_level
    if log_level >= 2:
        update_ongoing = False
        writeLine("\r[" + add_color("*", GREEN) + "] " + msg)


def debug(msg):
    global log_level
    if log_level >= 3:
        writeLine("[" + add_color("D", GRAY) + "] " + msg)


def info(msg):
    global log_level
    if log_level >= 2:
        writeLine("[" + add_color("+", BLUE) + "] " + msg)


def warn(msg):
    global log_level
    if log_level >= 1:
        writeLine("[" + add_color("!", RED) + "] " + msg)


def success(msg):
    pass
