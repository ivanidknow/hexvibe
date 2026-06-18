// Vulnerable: VUL-CVE-2015-8792
2015-10-17  Moritz Bunkus  <moritz@bunkus.org>
// --- KaxBlock.cpp ---
            SizeRead = LastBufferSize;
            FrameSize = ReadCodedSizeValue(BufferStart + Mem.GetPosition(), SizeRead, SizeUnknown);
            SizeList[0] = FrameSize;
            Mem.Skip(SizeRead);
...
              SizeRead = LastBufferSize;
              FrameSize += ReadCodedSizeSignedValue(BufferStart + Mem.GetPosition(), SizeRead, SizeUnknown);
              SizeList[Index] = FrameSize;
              Mem.Skip(SizeRead);
