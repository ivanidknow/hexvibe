// Vulnerable: JAVA-117
@RequestMapping("/redirect5")
public ModelAndView redirect5(@RequestParam("url") String url) {
    String view = "redirect:" + url;
    return new ModelAndView(view);
}
