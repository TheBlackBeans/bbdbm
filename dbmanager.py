#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""DBManager
Starts a daemon listening on localhost:1818
Logs can be found in logs/
Check `config' for the complete configuration
(including port and host).
In `defs/':
Check `dbcmd' for more information about
requests and communication;
Check `pdb' for more information about 
information storage;
Check `ids' for more information about
object representation, and their ids;
Check `types' for more information about
statis types that can be found in the database.
"""

import socket, os, sys, threading, datetime, traceback, io, configparser, signal
from dbinterface import Database, LoginError
from bininterface import read_int, read_float, read_string, write_int, write_float, write_string, gen_read_list, gen_write_list, read_bool, write_bool

try:
    import setproctitle
except ImportError:
    class A:
        def setproctitle(self, x):
            pass
    setproctitle = A()

import log

def _init_config(cfg):
    global SIZERECV, config
    config = cfg
    SIZERECV = int(config["socket"]["SIZERECV"])


class IdentiferGenerator:
    def __init__(self):
        self.curr = 1 # 0 is superuser
        self._free = set()
    def free(self, id_):
        if id_ < self.curr:
            self._free.add(id_)
    def get(self):
        if self._free:
            return self._free.pop()
        self.curr += 1
        return self.curr - 1

idgen = IdentiferGenerator()
    
class Daemon:
    def start(self):
        pid = os.fork()
        if pid > 0:
            pass
        else:
            os.setsid()
            self.pid = os.getpid()
            self.run()
            
class ConnectionListener(threading.Thread):
    def __init__(self, conn, adress, parent, id_):
        threading.Thread.__init__(self)
        self.conn = conn
        self.adress = adress
        self.parent = parent
        self.context = {"id": id_}
    def run(self):
        while True:
            cmd = self.conn.recv(SIZERECV)
            if not cmd: # connection broken/ended
                logger.write("Connection %s (from %s) ended" % (self.context["id"], print_adress(self.adress)), source="dbmanager", verbosity=1)
                logger.flush()
                idgen.free(self.context["id"])
                return
            offset, size = read_int(cmd)
            cmd = cmd[offset:]
            for i in range(size//SIZERECV):
                cmd += self.conn.recv(SIZERECV)
            if len(cmd) != size:
                logger.write("Connection %s sent broken command" % self.context["id"], source="dbmanager", verbosity=1, type_="warning")
            logger.write("Connection %s sent command %s" % (self.context["id"], read_int(cmd)[1]), source="dbmanager", verbosity=1)
            logger.flush()
            dbdaemon_lock.acquire()
            rtn_msg = self.parent.submit(cmd, self.conn.send, self.context)
    def kill(self):
        self.conn.close()
        signal.pthread_kill(self.ident, signal.SIGKILL)
        
def print_adress(adress):
    return "%s:%s" % (adress[0], adress[1])
            
class DatabaseManager(Daemon):
    def run(self):
        with open(config["daemon"]["pidfile"], "w") as f:
            f.write(str(self.pid))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((config["socket"]["host"], int(config["socket"]["port"])))
        self.socket.listen()
        self.database = Database(config, logger=logger)
        self._kills = []
        while True:
            conn, adress = self.socket.accept()
            logger.write("Received connection from %s" % print_adress(adress), source="dbmanager")
            id_ = idgen.get()
            logger.write("Giving id %s to connection from %s" % (id_, print_adress(adress)), source="dbmanager", verbosity=1)
            logger.flush()
            cl = ConnectionListener(conn, adress, self, id_)
            self._kills.append(cl.kill)
            cl.start()
    def submit(self, cmd, returner, context):
        pos, code = read_int(cmd)
        try:
            if code == 0:
                returner(write_int(0) + write_string(str(self.pid)))
            elif code == 1:
                returner(write_int(0))
                self.kill()
            elif code == 2:
                returner(write_int(0) + write_bool(self.database.is_open))
            elif code == 3:
                if self.database.is_open:
                    returner(write_int(0) + write_bool(False))
                else:
                    self.database.open()
                    returner(write_int(0) + write_bool(True))
            elif code == 4:
                if self.database.is_open:
                    self.database.close()
                    returner(write_int(0) + write_bool(True))
                else:
                    returner(write_int(0) + write_bool(False))
            elif code == 5:
                pos, user = read_string(cmd, pos)
                pos, passwd = read_string(cmd, pos)
                try:
                    self.database.login(user, passwd, context["id"])
                except LoginError as e:
                    returner(write_int(0) + write_bool(False) + write_string(repr(e)))
                else:
                    returner(write_int(0) + write_bool(True) + write_string(""))
            elif code == 6:
                pos, user = read_string(cmd, pos)
                self.database.user_instances[user].logout(context["id"])
                returner(write_int(0))
            elif code == 7:
                pos, user = read_string(cmd, pos)
                returner(write_int(0) + write_bool(self.database.user_instances[user].is_open))
            elif code == 8:
                pos, user = read_string(cmd, pos)
                self.database.user_instances[user].open(context["id"])
                returner(write_int(0))
            elif code == 9:
                pos, user = read_string(cmd, pos)
                self.database.user_instances[user].close(context["id"])
                returner(write_int(0))
            elif code == 10:
                pos, user = read_string(cmd, pos)
                pos, passwd = read_string(cmd, pos)
                self.database.create_user(user, passwd)
                returner(write_int(0))
            elif code == 11:
                pos, user = read_string(cmd, pos)
                if user in self.database.user_instances.keys():
                    self.database.user_instances[user].delete_user(context["id"])
                    returner(write_int(0))
                else:
                    returner(write_int(3))
            elif code == 12:
                pos, user = read_string(cmd, pos)
                result = write_int(0)
                if user in self.database.users.keys():
                    result += write_bool(True)
                else:
                    result += write_bool(False)
                if user in self.database.user_instances.keys():
                    result += write_bool(True) + write_bool(self.database.user_instances[user].ping(context["id"]))
                else:
                    result += write_bool(False) + write_bool(False)
                returner(result)
            elif code == 13:
                pos, user = read_string(cmd, pos)
                if user in self.database.user_instances.keys():
                    returner(write_int(0) + gen_write_list(write_string)(self.database.user_instances[user].list(context["id"])))
                else:
                    returner(write_int(3))
            elif code == 14:
                pos, user = read_string(cmd, pos)
                pos, request = gen_read_list(read_string)(cmd, pos)
                if request:
                    request = [request]
                if user in self.database.user_instances.keys():
                    self.database.user_instances[user].load(context["id"], *request)
                    returner(write_int(0))
                else:
                    returner(write_int(3))
            elif code == 15:
                pos, user = read_string(cmd, pos)
                if user in self.database.user_instances.keys():
                    returner(write_int(0) + gen_write_list(write_string)(self.database.user_instances[user].listl(context["id"])))
                else:
                    returner(write_int(3))
            elif code == 16:
                pos, user = read_string(cmd, pos)
                pos, request = gen_read_list(read_string)(cmd, pos)
                if request:
                    request = [request]
                if user in self.database.user_instances.keys():
                    self.database.user_instances[user].unload(context["id"], *request)
                    returner(write_int(0))
                else:
                    returner(write_int(3))
            elif code == 17:
                pos, user = read_string(cmd, pos)
                pos, name = read_string(cmd, pos)
                if user in self.database.user_instances.keys():
                    self.database.user_instances[user].delete_loaded_table(context["id"], name)
            else:
                returner(write_int(1))
    
        except:
            
            error = sys.exc_info()
            errorstr = io.StringIO()
            traceback.print_exception(*error, file=errorstr)
            error = errorstr.getvalue()[:-1]
            logger.write(error, type_='error', source="dbmanager")
            logger.flush()
            returner(write_int(2) + write_string(error))

        dbdaemon_lock.release()
    
    def kill(self, errcode=0):
        # errcode == 0: no problem
        logger.write("Dying with err code %s" % errcode, source="dbmanager", type_="info")
        logger.flush()
        self.socket.close()
        for kill in self._kills:
            kill()
        logger.close()
        with open(config["daemon"]["pidfile"], "w") as f:
            f.write("-1")
        sys.exit(errcode)
        
def start_daemon(verbosity=0, stdout=False):
    global logger, dbdaemon_lock, dbmanager
    setproctitle.setproctitle(config["daemon"]["proctitle"])
    logger = log.Logger(config["default"]["log_dir"].split(os.sep), verbosity=verbosity, stdout=stdout)
    logger.open()

    logger.write("Starting the daemon %s (v%s)..." % (config["main"]["vname"], config["main"]["version"]), source="dbmanager", type_="info")
    logger.flush()
    
    dbdaemon_lock = threading.Lock()
    dbmanager = DatabaseManager()
    try:
        dbmanager.start()
    except SystemExit:
        raise # let the sys.exit calls go trought
    except:
        with open(config["daemon"]["pidfile"], "w") as f:
            f.write("-1")
        logger.write("Daemon crashed...", source="dbmanager", type_="fatal")
        logger.flush()
        raise
    logger.write("Daemon successfully started!", source="dbmanager", type_="info")
    logger.flush()
        
if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read("config.ini")
    _init_config(config)
    start_daemon()
