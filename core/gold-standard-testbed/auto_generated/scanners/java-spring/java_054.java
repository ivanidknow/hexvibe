// Vulnerable: JAVA-054
@POST
@Path("/vulnerable")
@Produces(MediaType.APPLICATION_JSON)
public Map<String, String> doConcat(Pair pair) {
  HashMap<String, String> result = new HashMap<String, String>();
  result.put("Result", pair.getP1() + pair.getP2());
  return result;
}
@POST
@Path("/count")
@Produces(MediaType.APPLICATION_JSON)
