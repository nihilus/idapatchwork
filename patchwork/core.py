import re

import idautils
import idc

from DataTransferObjects import Selection, EmulationOutcome, ValidationOutcome
import config


##############################################
# patchwork core

def select(selector, memory, image_base):
    """
    if selector.hasFixedOffset():
        # TODO: probably perform regex match at this location to optionally enable grabbing a groupdict
        selection = Selection(selector.startOffset, transformator=selector.transformator)
        selection.codeRefsToFunction = [xref for xref in idautils.CodeRefsTo(associated_function, 0)]
        selection.codeRefsToMatch = [xref for xref in idautils.CodeRefsTo(image_base + match.start(), 0)]
        return [selection]
    """
    selections = []
    if selector.hasFixedOffset():
        selection_offset = image_base + selector.startOffset
        selection = Selection(selection_offset, transformator=selector.transformator, selection_groupdict={})
        associated_function = idc.LocByName(idc.GetFunctionName(selection_offset))
        selection.codeRefsToFunction = [xref for xref in idautils.CodeRefsTo(associated_function, 0)]
        selection.codeRefsToMatch = [xref for xref in idautils.CodeRefsTo(selection_offset, 0)]
        selections.append(selection)
        return selections
    for match in re.finditer(selector.regex, memory):
        associated_function = idc.LocByName(idc.GetFunctionName(image_base + match.start()))
        selection = Selection(image_base + match.start(), transformator=selector.transformator, selection_groupdict=match.groupdict())
        selection.codeRefsToFunction = [xref for xref in idautils.CodeRefsTo(associated_function, 0)]
        selection.codeRefsToMatch = [xref for xref in idautils.CodeRefsTo(image_base + match.start(), 0)]
        selections.append(selection)
    return selections


def emulate(emu, selection, resultCallback=None, maxInstructions=100):
    emu.debug(config.EMU_DEBUG_LEVEL)
    emu.setup_context()
    emu.set_register("EIP", selection.emulationStartOffset)
    if config.EMU_VERBOSE:
        print "[*] Starting emulation at 0x%08x" % (emu.get_register("EIP"))
    ins_executed = 0
    collected_code = []
    while not idc.GetMnem(emu.get_register("EIP")).startswith("ret") and ins_executed < maxInstructions:
        diasasm = emu.get_disasm()
        if diasasm and not diasasm[:4] in ("nop", "jmp ", "call"):
            collected_code.append(diasasm)
        try:
            emu.execute(steps=1)
        except:
            break
        ins_executed += 1
    if config.EMU_VERBOSE:
        emu.dump_regs()
        print "ESP: 0x%x" % emu.get_register("ESP")
        print "\n".join(collected_code)
        print "target: 0x%x" % emu.get_memory(emu.get_register("ESP"))
        print "steps executed: %d" % ins_executed
        print "[*] Ending emulation at 0x%08x" % (emu.get_register("EIP"))
        print "[*] Finished!"
    callbackResult = None
    try:
        callbackResult = resultCallback(emu)
    except:
        pass
    return EmulationOutcome(selection, ins_executed, collected_code, callbackResult)


def validate(patterns, emulation_outcome):
    positive_patterns = []
    for pattern in patterns:
        instructions = patterns[pattern]
        matches = True
        for ins_index, instruction in enumerate(instructions):
            if len(emulation_outcome.instructionTrace) < len(instructions) \
                    or not emulation_outcome.instructionTrace[ins_index].startswith(instruction):
                matches = False
                break
        if matches:
            positive_patterns.append(pattern)
    return ValidationOutcome(emulation_outcome, positive_patterns)


def transform(candidate, transformators):
    # candidate can be a Selection or ValidationOutcome and chosen transformator has to decide how to treat its input
    if candidate.transformator and candidate.transformator in transformators:
        return transformators[candidate.transformator](candidate)
    return False, []
