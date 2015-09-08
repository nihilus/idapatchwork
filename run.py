#!/usr/bin/env python

import sys
import time

import idautils

import patchwork.ida_lib as ida_lib
import patchwork.config as config

sys.path.append(config.PYEMU_PATH)
sys.path.append(config.PYEMU_PATH + "\lib")

from PyEmu import *


##############################################
# setup emulator

print "#" * 80
print "#" * 80

segments = [seg for seg in idautils.Segments()]
textstart = min(segments)
textend = idc.SegEnd(max(segments))
IMAGE_BASE = textstart
memory = ida_lib.get_memory(textstart, textend)
print "[+] memory (0x%x - 0x%x) extracted from IDA." % (textstart, textend)

LOAD_EMU = True
emu = IDAPyEmu()
emu.debug(0)

if LOAD_EMU:
    count = 0
    for offset, byte in enumerate(memory):
        emu.set_memory(textstart + offset, byte, size=1)
        count += 1
        if (count % 0x1000) == 0:
            sys.stdout.write(".")
            sys.stdout.flush()
    print "\n"
    print "[+] Text section (%d bytes) loaded into PyEmu memory." % len(memory)


##############################################
# run a stitch

from patchwork.stitches import NymaimDeobfuscation

emu.textstart = textstart
emu.textend = textend

nymaim = NymaimDeobfuscation.NymaimDeobfuscation(emu)
nymaim.run()

timestring = time.strftime("%Y-%m-%d_%H-%M-%S", time.gmtime(time.time()))
ida_lib.export_all(timestring + "_patchworked.bin")
