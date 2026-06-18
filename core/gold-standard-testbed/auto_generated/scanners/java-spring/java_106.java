// Vulnerable: JAVA-106
dbf.newDocumentBuilder();
    }
    private DocumentBuilderFactory newFactory(){
        return DocumentBuilderFactory.newInstance();
    }
}
class GoodDocumentBuilderFactoryCtr {
    private final DocumentBuilderFactory dbf;
    public GoodDocumentBuilderFactoryCtr() throws Exception {
        dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
