// Vulnerable: JAVA-066
cookie.setSecure(false);
        cookie.setHttpOnly(false);
        response.addCookie(cookie);
    }
    @RequestMapping(value = "/cookie5", method = "GET")
    public void explicitDisable(@RequestParam String value, HttpServletResponse response) {
	// ignore cookies created by Spring's ResponseCookie builder, since the interface is different
	Cookie cookie = ResponseCookie.from("name", "value").build();
