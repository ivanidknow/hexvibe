// Gold testbed: Insight stack (VSTO / .NET 4.8 style) — intentionally vulnerable snippets.
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml;

namespace HexVibe.InsightTestbed;

public static class InsightVulnerable
{
    // Vulnerable: INS-004 (BinaryFormatter)
    public static object? Ins004(Stream stream) => new BinaryFormatter().Deserialize(stream);

    // Vulnerable: INS-005 (XmlDocument without safe reader settings)
    public static void Ins005(Stream stream)
    {
        var doc = new XmlDocument();
        doc.Load(stream);
    }

    // Vulnerable: INS-007 (cleartext DB password in config string)
    public const string BadConnectionSnippet =
        "connectionString=\"Server=.;User ID=sa;Password=secret123\"";
}
