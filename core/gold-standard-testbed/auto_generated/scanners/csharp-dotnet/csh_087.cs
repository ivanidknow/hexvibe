// Vulnerable: CSH-087
Console.WriteLine(myReader.ReadElementContentAsString());
        }
    }
    Console.ReadLine();
}
public void ReaderGood(string userInput)
{
    XmlTextReader myReader = new XmlTextReader(new StringReader(userInput));
    myReader.DtdProcessing = DtdProcessing.Prohibit;
