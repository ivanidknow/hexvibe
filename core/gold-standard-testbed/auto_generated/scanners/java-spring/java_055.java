// Vulnerable: JAVA-055
@GET
@Path("/images/{image}")
@Produces("images/*")
public Response getImage(@javax.ws.rs.PathParam("image") String image) {
    File file = new File("resources/images/", image); //Weak point
    if (!file.exists()) {
        return Response.status(Status.NOT_FOUND).build();
    }
    return Response.ok().entity(new FileInputStream(file)).build();
}
