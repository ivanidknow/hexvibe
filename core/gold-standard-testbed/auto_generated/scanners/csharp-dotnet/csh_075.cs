// Vulnerable: CSH-075
return File.ReadAllBytes(filepath);
}
public static bytes[] GetFileSafe(string filename) {
    // Ensure that all path elements are safe path elements.
    if (string.IsNullOrEmpty(filename))
    {
        throw new ArgumentNullException("error");
    }
    filename = Path.GetFileName(filename);
