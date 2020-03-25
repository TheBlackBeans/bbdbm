# -*- coding: utf-8 -*-

from bininterface import *
import socket, sys

class UnknownCommand(BaseException): pass
class LoginError(BaseException): pass

class Connection:
    def __init__(self, adress="localhost", port=1818):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((adress, port))
    def _read(self):
        ret = self.socket.recv(1024)
        pos, retcode = read_int(ret)
        if retcode == 0:
            return ret[pos:]
        elif retcode == 1:
            raise UnknownCommand("Unknown command, nothing done nor returned")
        elif retcode == 2:
            pos, exception = read_string(ret, pos)
            print(exception)
            raise
        elif retcode == 3:
            raise LoginError("You need to be loged in to complete this action")
        else:
            raise ValueError("Unknown retcode %s" % retcode)
    def ping(self):
        self.socket.send(write_int(1) + write_int(0))
        ret = self._read()
        pos, pid = read_string(ret)
        return pid
    def kill(self):
        self.socket.send(write_int(1) + write_int(1))
        ret = self._read()
        self.socket.close()
    def dbstat(self):
        self.socket.send(write_int(1) + write_int(2))
        ret = self._read()
        pos, is_open = read_bool(ret)
        return is_open
    def dbopen(self):
        self.socket.send(write_int(1) + write_int(3))
        ret = self._read()
        pos, is_open = read_bool(ret)
        return is_open
    def dbclose(self):
        self.socket.send(write_int(1) + write_int(4))
        ret = self._read()
        pos, is_close = read_bool(ret)
        return is_close
    def login(self, user, passwd):
        msg = write_int(5) + write_string(user) + write_string(passwd)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
        pos, success = read_bool(ret)
        pos, reason = read_string(ret)
        return success, reason
    def logout(self, user):
        msg = write_int(6) + write_string(user)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
    def status(self, user):
        msg = write_int(7) + write_string(user)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
        pos, status = read_bool(ret)
        return status
    def open(self, user):
        msg = write_int(8) + write_string(user)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
    def close(self, user):
        msg = write_int(9) + write_string(user)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
    def create(self, user, passwd):
        msg = write_int(10) + write_string(user) + write_string(passwd)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
    def delete(self, user):
        msg = write_int(11) + write_string(user)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
    def ustat(self, user):
        msg = write_int(12) + write_string(user)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
        pos, q1 = read_bool(ret)
        pos, q2 = read_bool(ret, pos)
        pos, q3 = read_bool(ret, pos)
        return q1, q2, q3
    def list(self, user):
        msg = write_int(13) + write_string(user)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
        pos, tables = gen_read_list(read_string)(ret)
        return tables
    def load(self, user, tables):
        msg = write_int(14) + write_string(user) + gen_write_list(write_string)(tables)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
    def listl(self, user):
        msg = write_int(15) + write_string(user)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
        pos, tables = gen_read_list(read_string)(ret)
        return tables
    def unload(self, user, tables):
        msg = write_int(16) + write_string(user) + gen_write_list(write_string)(tables)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
    def delltab(self, user, table):
        msg = write_int(17) + write_string(user) + write_string(table)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
    def delftab(self, user, table):
        msg = write_int(18) + write_string(user) + write_string(table)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
    def newtable(self, user, table, header):
        msg = write_int(19) + write_string(user) + write_string(table) + gen_write_list(write_int)(header)
        self.socket.send(write_int(len(msg)) + msg)
        ret = self._read()
        
