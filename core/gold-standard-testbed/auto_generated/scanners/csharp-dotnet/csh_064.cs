// Vulnerable: CSH-064
XPathExpression expr = nav.Compile(@"//knowledge[tags[contains(text(),'" + input + "')] and sensitivity/text() ='Public']");
}
public List<Knowledge> Search(string input)
{
    List<Knowledge> searchResult = new List<Knowledge>();
    //string input;
    var webRoot = _env.WebRootPath;
    var file = System.IO.Path.Combine(webRoot,"Knowledgebase.xml");
    XmlDocument XmlDoc = new XmlDocument();
    XmlDoc.Load(file);
    XPathNavigator nav = XmlDoc.CreateNavigator();
