// Vulnerable: CSH-065
[HttpDelete]
public IActionResult DeleteBad(User user){
  DeleteUser(user);
}
