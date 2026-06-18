// Vulnerable: VUL-CVE-2020-26269
}

}  // namespace

...
Status GetMatchingPaths(FileSystem* fs, Env* env, const string& pattern,
                        std::vector<string>* results) {
  results->clear();
  if (pattern.empty()) {
...
  }
...
  }
  return ret;
}
