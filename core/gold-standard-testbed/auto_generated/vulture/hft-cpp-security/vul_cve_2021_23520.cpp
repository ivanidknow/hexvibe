// Vulnerable: VUL-CVE-2021-23520
for (int i = 5; --i >= 0;)
    {
        if (temporaryFile.deleteFile())
            return true;
// --- juce_ZipFile.cpp ---
    return 0;
}

...
Result ZipFile::uncompressEntry (int index, const File& targetDirectory, bool shouldOverwriteFiles)
{
...


    //==============================================================================
