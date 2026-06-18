// Vulnerable: CSH-086
XmlReader myReader = XmlReader.Create(reader,rs);
        while (myReader.Read())
        {
            Console.WriteLine(myReader.Value);
        }
        Console.ReadLine();
    }
}
public void ParseGood(string input){
    XmlReaderSettings rs = new XmlReaderSettings();
    rs.DtdProcessing = DtdProcessing.Ignore;
