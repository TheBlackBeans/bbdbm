#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse, psutil, sys, socket, configparser, os
from carrot import write_int, read_int

parser = argparse.ArgumentParser(prog="daemonmanager", description="Control and watch dbmanager daemon")
parser.add_argument("--verbose", "-v", action="count", help="level of verbosity")
parser.add_argument("--print", "-p", action="store_true", help="print to stdout logs")
parser.add_argument("--force", "-f", action="store_true", help="automatically answers all questions by the default choice")
parser.add_argument("--config", "-c", default="config.ini", help="select the config file")
parser.add_argument("command", choices=["status", "poweron", "poweroff", "restart", "start", "shutdown", "stop"], default=None, help="status: ping\npoweron|start: start the daemon\npoweroff|shutdown|stop: stop the daemon\nrestart: restart the daemon")
result = parser.parse_args()

config = configparser.ConfigParser()
config.read(result.config)

command = result.command
verbosity = result.verbose or int(config["default"]["verbosity"]) # default if result.verbosity == None
stdout = result.print
force = result.force

yes = {"y", "yes"}
no = {"n", "no"}

def prompt(msg, d="y"):
    if force:
        return 0 if d in yes else 1
    if d in yes:
        options = "[Y/n]"
    else:
        options = "[y/N]"
    r = input(msg + " " + options + " ")
    while r.lower().replace(" ","") not in yes.union(no).union({""}):
        r = input(msg + " " + options + " ")
    if r in yes:
        return 0
    elif r in no:
        return 1
    else:
        return 0 if d in yes else 1

def kill_daemon():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", 1818))
    r = 0
    try:
        s.send(write_int(1) + write_int(1))
        s.settimeout(1.)
        assert s.recv(1) == b"\00"
    except:
        r = prompt("Daemon having problems, do you want to force the kill?", d="n")
        if r == 0:
            os.kill(pid, 9)
    s.close()
    return r       
if not command:
    parser.print_help()
    sys.exit(0)
    
with open(".daemon.pid") as f:
    pid = f.read().replace("\n", "")

try:
    pid = int(pid)
except ValueError:
    print(".daemon.pid doesn't hold a pid")
    sys.exit(1)
if pid > 0:
    status = psutil.pid_exists(pid)
    if not status:
        with open(".daemon.pid", 'w') as f:
            f.write("-1")
else:
    status = False

if command == "status":
    print("Alive, with pid %s" % pid if status else "Dead")
elif command in {"poweron", "start"}:
    if status:
        print("Daemon is already alive")
    else:
        import dbmanager
        dbmanager._init_config(config)
        dbmanager.start_daemon(verbosity, stdout)
        print("Daemon is alive")
elif command in {"poweroff", "stop", "shutdown"}:
    if not status:
        print("Daemon is already dead")
    else:
        r = kill_daemon()
        if r == 1: sys.exit(1)
                
        print("Daemon is dead")
elif command == "restart":
    import dbmanager
    if not status:
        r = prompt("Daemon is already dead, do you want to start it?")
        if r == 0:
            dbmanager.start_daemon(verbosity, stdout)
    else:
        r = kill_daemon()
        if r == 1:
            print("ERROR: daemon is not dead, cannot start an other one")
            sys.exit(1)
        dbmanager.start_daemon(verbosity, stdout)
else:
    raise ValueError("Command is something ugly.")
