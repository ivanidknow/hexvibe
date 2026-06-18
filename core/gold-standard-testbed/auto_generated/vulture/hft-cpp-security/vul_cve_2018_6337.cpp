// Vulnerable: VUL-CVE-2018-6337
class BufferedRandomDevice {
 public:
  static constexpr size_t kDefaultBufferSize = 128;

...
};

BufferedRandomDevice::BufferedRandomDevice(size_t bufferSize)
  : bufferSize_(bufferSize),
...
    buffer_(new unsigned char[bufferSize]),
...
// --- RandomTest.cpp ---
  }
}
