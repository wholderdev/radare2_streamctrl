#!/usr/bin/python3

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

class FifoRead:

    def __init__(self, ttyf_in):
        self.ttyf_in = ttyf_in
        self.curText = ""
        self.curTextTotal = ""
        self.isRunning = False

    def start(self):
        self._thread = threading.Thread(target=self._read_thread).start()

    def _read_thread(self):
        self.isRunning = True
        while self.isRunning:
            curChar = os.read(self.ttyf_in, 1)
            if len(curChar) == 0:#curChar == "":
                self.isRunning = False
                break
            self.curText += curChar.decode("utf-8")
            self.curTextTotal += curChar.decode("utf-8")

    def read(self):
        toRet = self.curText
        self.curText = ""
        return toRet

    def readTotal(self):
        return self.curTextTotal

    def close(self):
        self.isRunning = False


class FifoWrite:

    def __init__(self, ttyf_out):
        self.ttyf_out = ttyf_out
        self.mq = queue.Queue()
        self.isRunning = False

    def start(self):
        self._thread = threading.Thread(target=self._write_thread).start()

    def _write_thread(self):
        self.isRunning = True
        while self.isRunning:
            toSend = self.mq.get()
            if toSend is not None:
                os.write(self.ttyf_out, toSend)
            self.mq.task_done()

    def write(self, toSend):
        self.mq.put(toSend)

    def close(self):
        self.isRunning = False
        self.mq.put(None)


class myr2wrapper:

    def __init__(self, exname):
        self.exname = exname
        self.tmproot = "tmp"

        master_fd_in, slave_fd_in = pty.openpty()
        master_fd_out, slave_fd_out = pty.openpty()

        self.ttyf_in = os.ttyname(slave_fd_in)
        self.ttyf_out = os.ttyname(slave_fd_out)
        self.rr2_file = "temp_ra2.rr2"#.format(self.tmproot)

        with open(self.rr2_file, 'w') as r2cf:
            #r2cf.write("process={0}\n".format(self.exname))
            r2cf.write("stdin={0}\n".format(self.ttyf_in))
            r2cf.write("stdout={0}\n".format(self.ttyf_out))
            #r2cf.write("stderr={0}\n".format(self.ttyf_name))

        self.ttyfw = FifoWrite(master_fd_in)
        self.ttyfr = FifoRead(master_fd_out)

        self.ttyfw.start()
        self.ttyfr.start()

        #-e dbg.profile=temp_ra2.rr2
        #self.r2 = r2pipe.open(self.exname, flags=['-e', "dbg.profile=temp_ra2.rr2", '-d'])
        self.r2 = r2pipe.open(self.exname, flags=['-r', self.rr2_file, '-d'])
        #   TODO: Figure out which of these I should remove, I don't need to do some of this
        #   This should be done, but not here (gets functions, third a tells r2 to name them)
        self.cmd("aaa")
        #   Breakpoint at main (definitely should remove, should be a user decision) 
        self.cmd("db main")
        #   Continue program (probably should move)
        self.cmd("dc")
        #   Get pid (not needed)
        self.cmd("dp")

    #   For testing, should probably remove
    def sendText(self, toSend):
        self.ttyfw.write(toSend)

    #   For testing, should probably remove
    def readText(self):
        return self.ttyfr.read()

    def execScript(self, sfname):
        with open(sfname) as sfofile:
            sfcont = sfofile.read()
            sflines = sfcont.split('\n')
            for sfline in sflines:
                self.r2.cmd(sfline)

    def analysisInit(self):
        #self.cmd('ood')
        self.cmd('aaa')
        self.functions = self.cmdj('aflj')

    def functionInfo(self, fcnName):
        self.printFunctions()
        self.cmd("s {0}".format(fcnName))
        self.cmd('pdf')
        self.cmd('pdg')

    def printFunctions(self):
        funFormat = "f: {0}0x{1:016X}: {2:32s}"
        funTypes = ["^sym", "^entry", "^main", "^fcn"]
        funDict = {}

        for function in self.functions:
            isMatched = False
            for funType in funTypes:
                sres = re.search(funType, function['name'])
                if sres:
                    funDict.setdefault(funType, []).append(function)
                    isMatched = True
            if not isMatched:
                funDict.setdefault("unmatched", []).append(function)

        for funlKey in funDict:
            funList = funDict[funlKey]
            print("key: {0}".format(funlKey))
            for function in funList:
                print(funFormat.format("\t\t", function['offset'], function['name']))
         
        #    for funkey in function:
        #        print("\t{0:12s} {1:16s}: {2}".format(funkey, str(type(function[funkey])), function[funkey]))

    def printRegisters(self):
        registers = self.cmdj('drj')
        print("Register Values:")

        pCount = 0
        for reg, value in registers.items():
            print("\t{0:8s}0x{1:016X}".format(reg + ":", value), end="")
            pCount += 1
            if pCount % 4 == 0:
                print("")
        print("")

    def saveFunFiles(self):
        pdfdir = "apdfs"
        pdgdir = "apdgs"
        if not os.path.exists(pdfdir):
            os.makedirs(pdfdir)
        if not os.path.exists(pdgdir):
            os.makedirs(pdgdir)

        for function in self.functions:
            with open("{0}/{1}.apdf".format(pdfdir, function['name']), 'w') as ffpdf:
                self.cmd("s {0}".format(function['name']))
                ffpdf.write(self.cmd("pdf"))
            with open("{0}/{1}.apdg".format(pdgdir, function['name']), 'w') as ffpdg:
                self.cmd("s {0}".format(function['name']))
                ffpdg.write(self.cmd("pdg"))

    def test1(self):
        #self.cmd('dc')

        for curfun in self.functions:
            print("\tcurfun[name]: \t{0}".format(curfun['name']))
            print("\tcurfun[offset]: \t{0:x}".format(curfun['offset']))

        isPrint = False
        isScanf = False
        isExit = False
        uInput = ""
        while uInput not in ['quit', 'stop']:
            print("---------------------")
            if isPrint or isScanf:
                received = self.ttyfr.read()
                recTotal = self.ttyfr.readTotal()
                if len(received) > 0:
                    print("Received:\n{0}".format(received))
                print("RecTotal:\n{0}".format(recTotal))
                uInput = input("t1$ ")

            if isExit:
                break

            if uInput in ["regs"]:
                self.printRegisters()
            elif uInput == "":
                hasCall = False

                rip = self.cmdj('drj')['rip']
                instruction = self.cmdj("pdj 1 @ {0}".format(rip))
                #print("\n\n{0}".format(rip, instruction[0]), end="")
                #for inkey in instruction[0]:
                #    print("\t{0}: {1}".format(inkey, instruction[0][inkey]))

                print("inst: {0}".format(instruction[0]['disasm']))
                print("0x{0:x}: {1}".format(rip, instruction[0]['opcode']))
                if "call" in instruction[0]['opcode']:
                    hasCall = "sym.imp" not in instruction[0]['disasm']
                    if not isPrint:
                        isPrint = "print" in instruction[0]['disasm']
                    isScanf = "scanf" in instruction[0]['disasm']
                    isExit = "sym.imp.exit" in instruction[0]['disasm']

                if isScanf:
                    self.ttyfw.write(bytes("AAAAAAAA\n", 'utf-8'))
                    input("\t(scanf)")

                if hasCall:
                    print("\nStep in")#, end="")
                    self.cmd("ds")
                else:
                    print("\nStep over 1")#, end="")
                    self.cmd("dso 1")

            #print("\n/---------------------")

    def cmd(self, cmdStr):
        if DEBUG:
            print("self.r2.cmd({0})".format(cmdStr))
        cmdRes = self.r2.cmd(cmdStr)
        return cmdRes

    def cmdj(self, cmdjStr):
        if DEBUG:
            print("self.r2.cmdj({0})".format(cmdjStr))
        return self.r2.cmdj(cmdjStr)

    def quit(self):
        self.ttyfw.close()
        self.ttyfr.close()
        self.r2.quit()

try:
    exfile = sys.argv[1]
except IndexError:
    print("{0} binary [script]".format(sys.argv[0]))
    sys.exit(0)

r2wr = myr2wrapper(exfile)
r2wr.analysisInit()
r2wr.saveFunFiles()

#r2script = None
if len(sys.argv) > 2:
    #r2script = sys.argv[2]
    #r2wr.execScript(r2script)
    r2wr.execScript(sys.argv[2])

qc = {
    "exit":         ["e", "exit", "quit"],
    "registers":    ["registers", "regs", "r"],
    "functions":    ["functions", "funcs", "f"],
    "test1":        ["test1", "t1"],
    "help":         ["h", "help"]
}


curCom = ""
while curCom not in qc["exit"]:
    if curCom in qc["registers"]:
        #r2wr.functionInfo("main")
        r2wr.printRegisters()
    elif curCom in qc["functions"]:
        r2wr.printFunctions()
    elif curCom in qc["test1"]:
        r2wr.test1()
    elif "s " in curCom:
        r2wr.sendText(curCom[2:])
    elif "read" == curCom:
        print(r2wr.readText())
    else:
        if curCom not in qc["help"] and curCom != "":
            print("Unrecognized Command: {0}".format(curCom))
        print("Commands")
        print(qc)
    curCom = input("run$ ")

r2wr.quit()
print("Main Thread: Done")
