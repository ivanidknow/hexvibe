// Vulnerable: JAVA-105
public static Object handleXml(InputStream in) {
    XMLDecoder d = new XMLDecoder(in);
    try {
        Object result = d.readObject(); //Deserialization happen here
        return result;
    }
    finally {
        d.close();
    }
}
