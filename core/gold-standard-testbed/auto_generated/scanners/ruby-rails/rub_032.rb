# Vulnerable: RUB-032
iseq.eval
iseq = RubyVM::InstructionSequence.compile('num = 1 + 2')
