# -*- coding: utf-8 *-*


import operator

import idautils
import idc


##############################################
# export all segments to file

# export_all("second_pass.bin")
# sys.exit()

def lrange(num1, num2=None, step=1):
    """
    Allows iteration over arbitrary numbers instead of dword long numbers.
    Credits go to:
    http://stackoverflow.com/questions/2187135/range-and-xrange-for-13-digit-numbers-in-python
    http://stackoverflow.com/users/263162/ricardo-cardenes
    """
    op = operator.__lt__

    if num2 is None:
        num1, num2 = 0, num1
    if num2 < num1:
        if step > 0:
            num1 = num2
        op = operator.__gt__
    elif step < 0:
        num1 = num2

    while op(num1, num2):
        yield num1
        num1 += step


def get_all_memory():
    result = ""
    start = [ea for ea in idautils.Segments()][0]
    end = idc.SegEnd(start)
    for ea in lrange(start, end):
        result += chr(idc.Byte(ea))
    return result


def export_all(filename):
    all_segments = get_all_memory()
    with open(filename, "wb") as f_out:
        f_out.write(all_segments)


##############################################
# helper functions.

def get_memory(start_addr, end_addr):
    current_byteoffset = start_addr
    memory = ""
    while current_byteoffset <= end_addr:
        # it's important to pick Byte and not GetOriginalByte here, otherwise same selections will be transformed multiple times
        current_byte = idc.Byte(current_byteoffset)
        memory += chr(current_byte)
        current_byteoffset += 1
    return memory


def get_multi_nop_buf(num_bytes):
    """
    return a buffer that will consist of as few nop instructions as possible
    FIXME: check compatibility with IDA
    As recommended by manual
    (post here: http://board.flatassembler.net/topic.php?t=5745
     gfx here:  https://imageshack.us/a/img49/2527/multibytenop3rl.png)
    """
    max_size = 1
    multi_nops = {0: "",
                  1: "\x90",
                  2: "\x66\x90",
                  3: "\x0f\x1f\x00",
                  4: "\x0f\x1f\x40\x00",
                  5: "\x0f\x1f\x44\x00\x00",
                  6: "\x90\x0f\x1f\x44\x00\x00",  # recommended was: "\x66\x0f\x1f\x44\x00\x00", but IDA seems to have trouble with 6 byte
                  7: "\x0f\x1f\x80\x00\x00\x00\x00",
                  8: "\x0f\x1f\x84\x00\x00\x00\x00\x00",
                  9: "\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"}
    return multi_nops[max_size] * (num_bytes / max_size) + multi_nops[num_bytes % max_size]


def patch_bytes(addr, bytes, is_analyzing_overwritten_bytes=False):
    """
    wrapper to patch multiple bytes at once
    """
    saved_bytes = ""
    for offset, byte in enumerate(bytes):
        saved_bytes += chr(idc.Byte(addr + offset))
        idc.PatchByte(addr + offset, ord(byte))
        idc.MakeCode(addr + offset)
    if is_analyzing_overwritten_bytes:
        idc.AnalyseArea(addr, addr + len(bytes))
    return


def nop_bytes(start_addr, num_bytes, is_analyzing_overwritten_bytes=False):
    idc.MakeUnknown(start_addr, num_bytes, idc.DOUNK_SIMPLE)
    patch_bytes(start_addr, get_multi_nop_buf(num_bytes), is_analyzing_overwritten_bytes)
