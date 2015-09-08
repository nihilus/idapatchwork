#!/usr/bin/env python

import sys, os, time, struct, re, string

import patchwork.ida_lib as ida_lib
import patchwork.config as config

sys.path.append(config.PYEMU_PATH)
sys.path.append(config.PYEMU_PATH + "\lib")

from PyEmu import *
 
emu = IDAPyEmu()
emu.debug(1)

START_EIP = 0x0

##############################################################################
# setup emulator

print "[*] Segments Selection: 0x%x - 0x%x" % (textstart, textend)
print "[*] Loading bytes into memory"

segments = [seg for seg in idautils.Segments()]
textstart = min(segments)
textend = idc.SegEnd(max(segments))
IMAGE_BASE = textstart
memory = ida_lib.get_memory(textstart, textend)
print "[+] memory (0x%x - 0x%x) extracted from IDA." % (textstart, textend)

emu = IDAPyEmu()
emu.debug(0)

count = 0
for offset, byte in enumerate(memory):
    emu.set_memory(textstart + offset, byte, size=1)
    count += 1
    if (count % 0x1000) == 0:
        sys.stdout.write(".")
        sys.stdout.flush()
print "\n"
print "[+] All segments (%d bytes) loaded into PyEmu memory." % len(memory)

##############################################################################
# set EIP in emulator and start execution of one instruction

emu.set_register("EIP", START_EIP)

print "[*] Starting emulation at 0x%08x" % (emu.get_register("EIP"))

emu.dump_regs()
emu.execute(steps=1)
emu.dump_regs()

print "[*] Ending emulation at 0x%08x" % (emu.get_register("EIP"))
print "[*] Finished!"

