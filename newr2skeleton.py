#!/usr/bin/env python3

import sys
import os
import stat

import r2pipe
import pty
import queue
import subprocess
import threading
import time

import re

DEBUG = False

class TTYRead:


    def __init__(self, ttyfile):
        self.file = ttyfile

        #   Thread to be set by start()
        self._thread = None

        #   Loop boolean for thread
        self.active = False
        #   Unread text
        self.tUnrd = ""
        #   All text ever received
        self.tHist = ""

    def start(self):
        self._thread = threading.Thread(target=self._threadLoop).start()

    def _threadLoop(self):
        self.active = True
        while self.active:
            try:
                curRec = os.read(self.file, 1)
            except OSError:
                continue

            if len(curRec) == 0:
                self.active = False
                break
            #   TODO: io.StringIO might be useful here instead of concats
            self.curText += curRec.decode("utf-8")
            self.curTextTotal += curRec.decode("utf-8")
        print("Read thread has exited")

    def getUnread(self):
        toRet = self.tUnrd
        self.tUnrd = ""
        return toRet

    def getHistory(self):
        return self.tHist

    def close(self):
        #   Originally was using file objects, not really needed now
        #       Using it to just set a bool for now, leaving it in case of new needs
        self.active = False


class TTYWrite:


    def __init__(self, ttyfile):
        self.file = ttyfile

        self.active = False
        self.wq = queue.Queue()

    def start(self):
        self._thread = threading.Thread(target=self._threadLoop).start()

    def _threadLoop(self):
        self.active = True
        while self.active:
            curSend = self.wq.get()
            if curSend is not None:
                os.write(self.file, curSend)
            self.wq.task_done()
        print("Write thread has exited")

    def write(self, toSend):
        self.wq.put(toSend)

    def close(self):
        self.active = False
        self.wq.put(None)


class R2Wrapper:


    def __init__(self, execFile, profFile, r2args=[]):
        self.exec = execFile
        self.prof = profFile

        self.r2args = r2args
        if "-d" not in self.r2args:
            self.r2args.append("-d")

        self.active = False
        self.cq = queue.Queue()
    
    def start(self):
        self._thread = threading.Thread(target=self._threadLoop).start()

    def _threadLoop(self):
        self.active = True
        self.r2 = r2pipe.open(self.exec, flags=self.r2args)

        while self.active:
            curCmd = self.cq.get()
            if curCmd is not None:
                #   TODO:
                print("TODO")
            self.cq.task_done()
        print("R2 thread has exited")

    def close(self):
        self.active = False
        self.cq.put(None)


class DbScriptingTool:


    def __init__(self, execFile, profExtra=None, r2args=[]):
        self.tmproot = "tmp"
        #   TODO: Oppertunity for other pofile options from profExtra
        self.prof = "temp_ra2.rr2"

        self.ttym_in, self.ttys_in = pty.openpty()
        self.ttym_out, self.ttys_out = pty.openpty()

        self.ttys_if = os.ttyname(self.ttys_in)
        self.ttys_of = os.ttyname(self.ttys_out)

        with open(self.prof, 'w') as r2f:
            r2f.write("stdin={0}\n".format(self.ttys_if))
            r2f.write("stdout={0}\n".format(self.ttys_of))

        self.ttywc = TTYWrite(self.ttym_in)
        self.ttyrc = TTYRead(self.ttym_out)
        self.r2wrc = R2Wrapper(execFile, self.prof, r2args)

    def start(self):
        self.ttywc.start()
        self.ttyrc.start()
        self.r2wrc.start()

    def close(self):
        self.ttywc.close()
        self.ttyrc.close()
        self.r2wrc.close()

        os.close(self.ttym_in)
        os.close(self.ttys_in)
        os.close(self.ttym_out)
        os.close(self.ttys_out)

print("Create dbst")
input("")
dbst = DbScriptingTool(sys.argv[1]) 
print("Starting Threads")
input("")
dbst.start()
print("Close")
input("")
dbst.close()
print("Exit")
input("")
