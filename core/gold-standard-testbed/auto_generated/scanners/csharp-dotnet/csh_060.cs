// Vulnerable: CSH-060
return View("Index", model);
}
public IActionResult Create([Bind(nameof(UserModel.Name))] UserModel model)
{
    context.SaveChanges();
