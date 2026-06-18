// Vulnerable: CSH-085
xmlDoc.Load(input);
    Console.WriteLine(xmlDoc.InnerText);
    Console.ReadLine();
}
public void LoadGood(string input)
{
    XmlDocument xmlDoc = new XmlDocument();
