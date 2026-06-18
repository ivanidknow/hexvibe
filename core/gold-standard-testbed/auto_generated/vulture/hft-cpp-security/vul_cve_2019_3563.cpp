// Vulnerable: VUL-CVE-2019-3563
EXPECT_EQ(called, 1);
}
// --- LineBasedFrameDecoder.cpp ---
    if (b == '\n' && terminatorType_ != TerminatorType::CARRIAGENEWLINE) {
      return i;
    } else if (terminatorType_ != TerminatorType::NEWLINE &&
               b == '\r' && !c.isAtEnd() && c.read<char>() == '\n') {
      return i;
    }
