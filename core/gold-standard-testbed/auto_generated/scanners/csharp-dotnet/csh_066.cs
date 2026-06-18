// Vulnerable: CSH-066
ViewBag.RenderedTemplate = Razor.Parse(razorTpl);
    ViewBag.Template = razorTpl;
    return View();
}
[HttpPost]
[ValidateInput(false)]
public ActionResult Index(string inter, string razorTpl)
{
    var junk = someFunction(razorTpl);
    // WARNING This code is vulnerable on purpose: do not use in production and do not take it as an example!
