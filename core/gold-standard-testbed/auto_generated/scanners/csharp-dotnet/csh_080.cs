// Vulnerable: CSH-080
return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
        else
        {
            ModelState.AddModelError("",
...
            if (IsLocalUrl(returnUrl))
            {
