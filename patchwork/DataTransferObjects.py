
##############################################
# DTOs


class Selector(object):

    def __init__(self, regex, transformator="", start_offset=0, end_offset=0):
        self.regex = regex
        self.transformator = transformator
        self.startOffset = start_offset
        self.endOffset = end_offset

    def hasFixedOffset(self):
        return self.startOffset and self.endOffset and self.startOffset == self.endOffset


class Selection(object):

    def __init__(self, selection_offset, transformator="", selection_groupdict={}):
        self.selectionOffset = selection_offset
        self.emulationStartOffset = selection_offset
        self.transformator = transformator
        self.selectionGroupdict = selection_groupdict
        self.codeRefsToFunction = []
        self.codeRefsToMatch = []


class EmulationOutcome(object):

    def __init__(self, selection, ins_executed, ins_trace, cb_result=None):
        self.selection = selection
        self.instructionsExecuted = ins_executed
        self.instructionTrace = ins_trace
        self.callbackResult = cb_result


class ValidationOutcome(object):

    def __init__(self, emulation_outcome, positive_patterns):
        self.emulation = emulation_outcome
        self.selection = emulation_outcome.selection
        self.positivePatterns = positive_patterns
        self.transformator = positive_patterns[0] if positive_patterns else None
