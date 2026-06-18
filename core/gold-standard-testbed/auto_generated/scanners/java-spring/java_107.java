// Vulnerable: JAVA-107
spf.newSAXParser();
    }
    private SAXParserFactory newFactory(){
        return SAXParserFactory.newInstance();
    }
}
class GoodSAXParserFactoryCtr {
    private final SAXParserFactory spf;
    public GoodSAXParserFactoryCtr() throws Exception {
        spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
