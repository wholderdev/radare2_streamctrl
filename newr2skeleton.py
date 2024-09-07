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
                print("TTYRead({0}): OSError".format(self.file))
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

        #   Thread to be set by start()
        self._thread = None

        #   Loop boolean for thread
        self.active = False
        #   Queued messages to write
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

        #   Thread to be set by start()
        self._thread = None

        #   Arguments for running radare2 for r2pipe
        self.r2args = r2args
        if "-d" not in self.r2args:
            self.r2args.append("-d")

        #   Loop boolean for thread
        self.active = False
        #   Queued commands for radare2
        self.cq = queue.Queue()

        #   TODO: Considering a dictionary with results
        #       queueCmd returns an "id" for the cmd
        #       Results are stored as { "id": results }
        #   This way I can have async while still saving the results.
        #       Maybe should clean up too after retrieving but idk
        self.incID = 0
        self.asyncResults = {}

    def getResult(self, resultID):
        if resultID in self.asyncResults:
            return self.asyncResults[resultID]
        else:
            return None

    def queueCmd(self, cmd, cmdType="cmd"):
        cmdID = self.incID
        self.incID += 1
        self.cq.put([cmd, cmdType, cmdID])
        return cmdID

    def cmd(self, cmd, cmdType="cmd"):
        if cmdType == "cmdj":
            return self.r2.cmdj(cmd)
        elif cmdType == "cmdJ":
            return self.r2.cmdJ(cmd)
        else: #if cmdType == "cmd":
            return self.r2.cmd(cmd)
    
    def start(self):
        self._thread = threading.Thread(target=self._threadLoop).start()

    def _threadLoop(self):
        self.active = True
        self.r2 = r2pipe.open(self.exec, flags=self.r2args)

        while self.active:
            cmd, cmdType, cmdID = self.cq.get()
            if cmd is not None:
                #   TODO: Should probably remove
                results = self.cmd(cmd, cmdType)
                self.asyncResults[cmdID] = [cmd, cmdType, results]
            self.cq.task_done()
        print("R2 thread has exited")

    def close(self):
        self.active = False
        self.cq.put([None, None])
        self.r2.quit()


class DbScriptingTool:


    def __init__(self, execFile, profExtra, r2args):
        self.tmproot = "tmp"
        #   TODO: Oppertunity for other pofile options from profExtra
        self.prof = "{0}/temp_ra2.rr2".format(self.tmproot)

        if not os.path.exists(self.tmproot):
            os.makedirs(self.tmproot)

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

    def startThreads(self):
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


class TestDST(DbScriptingTool):


    def __init__(self, execFile, profExtra=None, r2args=[]):
        super().__init__(execFile, profExtra=profExtra, r2args=r2args)

    def test1(self):
        self.r2wrc.cmd("ood")
        self.r2wrc.cmd("aaa")
        res1ID = self.r2wrc.queueCmd("afl")
        res2ID = self.r2wrc.queueCmd("aflj", "cmdj")
        return [res1ID, res2ID]

    def test1res(self, resList):
        res1 = self.r2wrc.getResult(resList[0])
        res2 = self.r2wrc.getResult(resList[1])
        print("res1")
        print(res1)
        print("res2")
        print(res2)


input("Press Enter To Create DBST\n")
#dbst = DbScriptingTool(sys.argv[1])
dbst = TestDST(sys.argv[1])
time.sleep(1)
input("\nPress Enter To Start Threads\n")
dbst.startThreads()
time.sleep(1)
input("\nPress Enter To Run Test1\n")
results = dbst.test1()
time.sleep(1)
input("\nPress Enter To Print Test1 Async Results\n")
dbst.test1res(results)
time.sleep(1)
input("\nPress Enter To End Threads And Close The Program\n")
dbst.close()
time.sleep(1)
input("\nEnd: Press Enter\n")
