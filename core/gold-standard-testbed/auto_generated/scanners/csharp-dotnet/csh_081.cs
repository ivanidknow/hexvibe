// Vulnerable: CSH-081
public void Validate5(string search)
{
    var pattern = @"^A(B|C+)+D";
    var result = Regex.Match(search, pattern, new RegexOptions { });
}
