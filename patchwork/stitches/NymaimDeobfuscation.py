import sys
import struct

import idautils
import idc

from patchwork.DataTransferObjects import Selector, Selection
import patchwork.ida_lib as ida_lib
import patchwork.core as core

##############################################
# patterns

push_push_call_regex = (
    r"\x68(?P<operand_1>[\S\s]{4})"
    r"\x68(?P<operand_2>[\S\s]{4})"
    r"\xE8"
)

push_call_regex = (
    r"\x68(?P<operand_1>[\S\s]{4})"
    r"\xE8"
)

push_reg_regex = (
    r"\x6a(?P<operand_1>[\x30-\x37]{1})"
    r"\xE8"
)

xor_reg_regex = (
    r"\x53"
    r"\xBB(?P<operand_1>[\S\s]{4})"
    r"\x31\xD8"
    r"\x5B"
    r"\xC3"
)

mov_eax_regex = (
    r"\xB8(?P<operand_1>[\S\s]{4})"
    r"\xC3"
)

ppc_validators = {
    "call_detour": [
        'push dword',
        'push dword',
        'push ebp',
        'mov ebp,esp',
        'push eax',
        'mov eax,[ebp+0x4]',
        'mov [ebp+0x10],eax',
        'mov eax,[ebp+0xc]',
        '',  # contains the operand -> add, sub, xor
        'add [ebp+0x4],eax',
        'pop eax',
        'leave'],
    "short_call_detour": [
        'push dword',
        'push dword',
        'push ebp',
        'mov ebp,esp',
        'push eax',
        'mov eax,[ebp+0xc]',
        '',  # contains the operand -> add, sub, xor
        'add [ebp+0x4],eax',
        'pop eax',
        'leave'],
    "jump_dual_detour": [
        'push dword',
        'push dword',
        'push ebp',
        'mov ebp,esp',
        'push eax',
        'push ecx',
        'mov eax,[ebp+0xc]',
        'mov ecx,[ebp+0x8]',
        'lea eax,[eax+ecx]',
        'mov ecx,[ebp+0x4]',
        'lea eax,[eax+ecx]',
        'mov [ebp+0x4],eax',
        'pop ecx',
        'pop eax',
        'leave'],
}

pc_validators = {
    "jump_single_detour": [
        'push dword',
        'push ebp',
        'mov ebp,esp',
        'push eax',
        'push ecx',
        'mov eax,[ebp+0x8]',
        'mov ecx,[ebp+0x4]',
        'mov ecx,[ecx]',
        '',  # contains the operand -> add, sub, xor
        'add [ebp+0x4],eax',
        'pop ecx',
        'pop eax',
        'leave'],
    "jump_single_detour_2": [
        'push dword',
        'push ebp',
        'mov ebp,esp',
        'push eax',
        'push ecx',
        'mov ecx,[ebp+0x4]',
        'mov ecx,[ecx',
        'mov eax,[ebp+0x8]',
        'lea eax,[eax+ecx]',
        'mov ecx,[ebp+0x4]',
        'lea eax,[eax+ecx]',
        'mov [ebp+0x4],eax',
        'pop ecx',
        'pop eax',
        'leave']
}

pr_validators = {
    "push_reg_deobfuscation": [
        'push byte',
        'cmp dword [esp+0x4]']
}


##############################################
# Stitch


class NymaimDeobfuscation():

    def __init__(self, emulator):
        # super(NymaimDeobfuscation, self).__init__(emulator)
        self.emulator = emulator
        self.memory = self.emulator.get_memory(emulator.textstart, emulator.textend - emulator.textstart)
        self.transformators = {
            "push_reg_deobfuscation": self._deobfuscate_push_reg,
            "call_detour": self._deobfuscate_call_detour,
            "short_call_detour": self._deobfuscate_call_detour,
            "jump_dual_detour": self._deobfuscate_jump_dual_detour,
            "jump_single_detour": self._deobfuscate_jump_single_detour,
            "jump_single_detour_2": self._deobfuscate_jump_single_detour,
            "xor_eax": self._deobfuscate_xor_eax,
            "mov_eax": self._deobfuscate_mov_eax,
        }

    def run(self):
        selector = Selector(push_push_call_regex)
        ppc_selections = core.select(selector, self.memory, self.emulator.textstart)
        ppc_validations = []
        print "\nFound %d ppc_selection hits." % len(ppc_selections)
        ppc_validations = self.validate_selections(ppc_selections, ppc_validators)

        selector = Selector(push_call_regex)
        pc_selections = core.select(selector, self.memory, self.emulator.textstart)
        pc_validations = []
        print "\nFound %d pc_selection hits." % len(pc_selections)
        pc_validations = self.validate_selections(pc_selections, pc_validators)

        selector = Selector(push_reg_regex)
        pr_selections = core.select(selector, self.memory, self.emulator.textstart)
        pr_validations = []
        print "\nFound %d pr_selection hits." % len(pr_selections)
        pr_validations = self.validate_selections(pr_selections, pr_validators)

        selector = Selector(xor_reg_regex, transformator="xor_eax")
        xr_selections = core.select(selector, self.memory, self.emulator.textstart)
        print "\nFound %d xr_selection hits (no validation required)." % len(xr_selections)

        selector = Selector(mov_eax_regex, transformator="mov_eax")
        me_selections = core.select(selector, self.memory, self.emulator.textstart)
        print "\nFound %d me_selection hits (no validation required)." % len(me_selections)

        print "\n** Results:"
        print "ppc - %d/%d validated hits" % (len([hit for hit in ppc_validations if hit.positivePatterns]), len(ppc_selections))
        print "pc - %d/%d validated hits" % (len([hit for hit in pc_validations if hit.positivePatterns]), len(pc_selections))
        print "pr - %d/%d validated hits" % (len([hit for hit in pr_validations if hit.positivePatterns]), len(pr_selections))
        print "xr - %d hits" % len(xr_selections)
        print "me - %d hits" % len(me_selections)

        num_all_transformations = 0
        fixed_offsets = set([])
        for candidates in [pr_validations, ppc_validations, pc_validations, xr_selections, me_selections]:
            for candidate in candidates:
                num_transformations, offsets = core.transform(candidate, self.transformators)
                num_all_transformations += num_transformations
                fixed_offsets.update(offsets)
        print "performed %d (hopefully) successful transformations" % num_all_transformations
        print "fixed offsets (%d): " % len(fixed_offsets)
        # print "undefine_offsets = ["
        # for offset in fixed_offsets:
        #     print "    0x%x," % offset
        # print "]"

    def emulate_single(self, start_addr):
        result = core.emulate(self.emulator, Selection(start_addr), self._cbCatchDetourAddress)
        print "details for 0x%x" % (result.selection.selectionOffset)
        for ins in result.instructionTrace:
            print ins
        print result.instructionTrace
        sys.exit()

    def validate_selections(self, selections, validators):
        emu_outcomes = []
        for index, selection in enumerate(selections):
            if (index % 50) == 0:
                sys.stdout.write(".")
                sys.stdout.flush()
            emu_outcomes.append(core.emulate(self.emulator, selection, self._cbCatchDetourAddress))

        validations = []
        for emu_outcome in emu_outcomes:
            validation = core.validate(validators, emu_outcome)
            if validation:
                validations.append(validation)
        return validations

    def _cbCatchDetourAddress(self, emulator):
        return emulator.get_memory(emulator.get_register("ESP"))

    def updateCallXref(self, source, new_dest):
        orig_dest = [x for x in idautils.XrefsFrom(source) if x != source + 5]
        if orig_dest:
            pass
            # print "from 0x%x to 0x%x becomes 0x%x to 0x%x" % (source, orig_dest[0].to, source, new_dest)
            # idc.DelCodeXref(source, orig_dest[0])
            # idc.DelCodeXref(source, new_dest)
        else:
            "didn't obtain orig address... 0x%x" % source

    def _deobfuscate_push_reg(self, validation_outcome):
        obfuscation_start_addr = validation_outcome.selection.selectionOffset
        # reg IDs: EAX - 0x30, EDX: 0x31, ... (was 0x31, ... in older versions?)
        reg_id = idc.Byte(obfuscation_start_addr + 1)
        # rewrite deobfuscation as <6x NOP>, <push reg> where reg can be numerically derived from
        # reg ID by adding 0x1F. E.g. EAX has parameter 31, so <push EAX> has opcode byte 0x50
        deobfuscated = ida_lib.get_multi_nop_buf(6) + chr(reg_id + 0x20)
        ida_lib.patch_bytes(obfuscation_start_addr, deobfuscated)
        return 1, []

    def _deobfuscate_call_detour(self, validation_outcome):
        obfuscation_start_addr = validation_outcome.selection.selectionOffset
        rel_call_offset = validation_outcome.emulation.callbackResult - (obfuscation_start_addr + 10 + 5)
        deobfuscated_call = "\x90" * 10 + "\xE8" + struct.pack("I", (rel_call_offset) & 0xffffffff)
        ida_lib.patch_bytes(obfuscation_start_addr, deobfuscated_call)
        self.updateCallXref(obfuscation_start_addr + 10, validation_outcome.emulation.callbackResult)

        rel_s = obfuscation_start_addr + 5 + 5 - self.emulator.textstart + 1
        dw = self.memory[rel_s:rel_s + 4]
        fixed_destination = (5 + obfuscation_start_addr + 5 + 5 + struct.unpack("I", dw)[0]) & 0xffffffff

        return 1, [fixed_destination]

    def _deobfuscate_jump_dual_detour(self, validation_outcome):
        obfuscation_start_addr = validation_outcome.selection.selectionOffset
        rel_jmp_offset = validation_outcome.emulation.callbackResult - (obfuscation_start_addr + 10 + 5)
        deobfuscated_jmp = "\x90" * 10 + "\xE9" + struct.pack("I", (rel_jmp_offset) & 0xffffffff)
        ida_lib.patch_bytes(obfuscation_start_addr, deobfuscated_jmp)
        self.updateCallXref(obfuscation_start_addr + 10, validation_outcome.emulation.callbackResult)

        rel_s = obfuscation_start_addr + 5 + 5 - self.emulator.textstart + 1
        dw = self.memory[rel_s:rel_s + 4]
        fixed_destination = (5 + obfuscation_start_addr + 5 + 5 + struct.unpack("I", dw)[0]) & 0xffffffff

        return 1, [fixed_destination]

    def _deobfuscate_jump_single_detour(self, validation_outcome):
        obfuscation_start_addr = validation_outcome.selection.selectionOffset
        rel_jmp_offset = validation_outcome.emulation.callbackResult - (obfuscation_start_addr + 5 + 5)
        deobfuscated_jmp = "\x90" * 5 + "\xE9" + struct.pack("I", (rel_jmp_offset) & 0xffffffff)
        ida_lib.patch_bytes(obfuscation_start_addr, deobfuscated_jmp)
        self.updateCallXref(obfuscation_start_addr + 5, validation_outcome.emulation.callbackResult)
        # replace the post jump bytes with NOP to improve IDA's code recognition
        ida_lib.patch_bytes(obfuscation_start_addr + 5 + 5, ida_lib.get_multi_nop_buf(4))

        rel_s = obfuscation_start_addr + 5 - self.emulator.textstart + 1
        dw = self.memory[rel_s:rel_s + 4]
        fixed_destination = (5 + obfuscation_start_addr + 5 + struct.unpack("I", dw)[0]) & 0xffffffff

        return 1, [fixed_destination]

    def _deobfuscate_xor_eax(self, selection_outcome):
        num_deobfuscations = 0
        for referencing_call in selection_outcome.codeRefsToFunction:
            obfuscation_start_addr = referencing_call
            deobfuscated_xor = "\x35" + selection_outcome.selectionGroupdict["operand_1"]
            ida_lib.patch_bytes(obfuscation_start_addr, deobfuscated_xor)
            num_deobfuscations += 1
        return num_deobfuscations, []

    def _deobfuscate_mov_eax(self, selection_outcome):
        num_deobfuscations = 0
        for referencing_call in selection_outcome.codeRefsToFunction:
            obfuscation_start_addr = referencing_call
            deobfusbcated_mov = "\xb8" + selection_outcome.selectionGroupdict["operand_1"]
            ida_lib.patch_bytes(obfuscation_start_addr, deobfusbcated_mov)
            num_deobfuscations += 1
        return num_deobfuscations, []
