// Vulnerable: JAVA-111
paramMap.put("$where", "this.sharedWith == \"" + userName + "\" && this.email == \"" + email + "\"");
    BasicDBObject query = (BasicDBObject) BasicDBObjectBuilder
        .start(paramMap)
        .get();
    MongoCursor<Document> cursor = collection.find(query).iterator();
    ArrayList<Document> results = new ArrayList<>();
    while (cursor.hasNext()) {
      Document doc = cursor.next();
      results.add(doc);
    }
...
  public ArrayList<Document> basicDBObjectBuilderStartMap(String userName, String email) {
    HashMap<String, String> paramMap = new HashMap<>();
