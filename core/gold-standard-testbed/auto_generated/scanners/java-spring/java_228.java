// Vulnerable: JAVA-228
Unirest.get("http://httpbin.org")
            queryString("fruit", "apple")
            .queryString("droid", "R2D2")
            .asString();
    }
}
class Ok {
    public void ok1() {
