// Vulnerable: CSH-001 (CSharpScript evaluate untrusted input)
var result = await CSharpScript.EvaluateAsync(expr);
// Vulnerable: CSH-002 (Process.Start command injection)
Process.Start("cmd.exe", "/c ping " + host);
// Vulnerable: CSH-003 (Shell execute user command)
Process.Start(new ProcessStartInfo("bash", "-c " + cmd) { UseShellExecute = true });
// Vulnerable: CSH-004 (Type.GetType from user input)
var t = Type.GetType(typeName);
// Vulnerable: CSH-005 (Reflective invoke user method)
target.GetType().GetMethod(method).Invoke(target, null);
// Vulnerable: CSH-006 (Unsafe ORDER BY fragment)
var sql = $"SELECT * FROM users ORDER BY {order}";
// Vulnerable: CSH-007 (Compile and run untrusted code)
CompileAndRun(code);
// Vulnerable: CSH-008 (JS engine execute untrusted script)
engine.Execute(script);
// Vulnerable: CSH-009 (Unsafe deserialization — BinaryFormatter / TypeNameHandling.All)
formatter.Deserialize(stream);
JsonConvert.DeserializeObject(json, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
// Vulnerable: CSH-010 (XXE — XmlDocument XmlResolver)
var doc = new XmlDocument();
doc.XmlResolver = new XmlUrlResolver();
doc.Load(reader);
// Vulnerable: CSH-011 (Insecure cookie flags)
var badOpts = new CookieOptions { Path = "/" };
Response.Cookies.Append("session", token, badOpts);
// Vulnerable: CSH-012 (Hardcoded secrets)
var defaultConnection = "Server=db;User=sa;Password=SuperSecret123";
var apiKey = "prod-api-key-12345";
// Vulnerable: CSH-013 (Weak crypto MD5/SHA1)
using (var md5 = MD5.Create()) { }
using (var sha1 = SHA1.Create()) { }
// Vulnerable: CSH-014 (Open redirect)
return Redirect(request.Query["redirect"]);
// Vulnerable: CSH-015 (Certificate validation bypass)
handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
// Vulnerable: CSH-016 (Weak password hashing — raw bytes + hash)
var bytes = Encoding.UTF8.GetBytes(password);
SHA256.Create().ComputeHash(bytes);

// Vulnerable: CSH-017 (Office HTML Injection)
mailItem.HTMLBody = userHtml;
worksheet.Cells[row, col].Formula = "=" + userInput;
// Vulnerable: CSH-018 (VSTO macro command execution)
Globals.ThisAddIn.Application.Run(userMacro);
// Vulnerable: CSH-019 (Banned BinaryFormatter Deserialize)
new BinaryFormatter().Deserialize(stream);
// Vulnerable: CSH-020 (Unsafe DataSet.ReadXml)
dataSet.ReadXml(userStream);
// Vulnerable: CSH-021 (Unsafe P/Invoke marshaling)
[DllImport("user32.dll")] static extern int MessageBox(string text);
// Vulnerable: CSH-022 (Assembly load from user path)
Assembly.LoadFrom(pathFromRequest);
// Vulnerable: CSH-023 (ASP.NET Mass Assignment entity binding)
public IActionResult Update(UserEntity entity) { return Ok(); }
// Vulnerable: CSH-024 (Unsafe AutoMapper profile)
CreateMap<UserDto, UserEntity>();
// Vulnerable: CSH-025 (JWT issuer/audience validation disabled)
ValidateIssuer = false; ValidateAudience = false;
// Vulnerable: CSH-026 (OAuth redirect URI not validated)
return Redirect(returnUrl);
// Vulnerable: CSH-027 (Insecure file upload)
System.IO.File.WriteAllBytes(path, bytesFile);
// Vulnerable: CSH-028 (Path traversal in PhysicalFile)
return PhysicalFile(basePath + name, "application/octet-stream");
// Vulnerable: CSH-029 (Missing anti-forgery)
[HttpPost] public IActionResult Transfer() { return Ok(); }
// Vulnerable: CSH-030 (.NET 4.8 insecure session config)
var sessionCookie = new CookieOptions { HttpOnly = false, Secure = false };
// Vulnerable: CSH-031 (Json.NET TypeNameHandling unsafe)
JsonConvert.DeserializeObject(payload, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
// Vulnerable: CSH-032 (ASP.NET request validation disabled)
// web.config: <pages validateRequest="false" />
// Vulnerable: CSH-033 (Weak TLS protocol negotiation)
ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
// Vulnerable: CSH-034 (Insecure random for security token)
var otp = new Random().Next(100000, 999999).ToString();
// Vulnerable: CSH-035 (Sensitive data in logs)
logger.LogInformation("pwd={pwd}", password);
// Vulnerable: CSH-036 (LDAP injection)
var filter = "(uid=" + user + ")";
// Vulnerable: CSH-037 (Regex DoS)
var re = new Regex("(a+)+$");
// Vulnerable: CSH-038 (XML signature validation bypass)
if (xmlSignature != null) { return true; }
// Vulnerable: CSH-039 (gRPC metadata trust)
var role = context.RequestHeaders.GetValue("x-role");
// Vulnerable: CSH-040 (GraphQL over-posting)
public class UserGraph { public string PasswordHash { get; set; } }
// Vulnerable: CSH-041 (EF FromSqlRaw injection)
var rows = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}");
// Vulnerable: CSH-042 (Telemetry export without scrubbing)
activity.SetTag("auth.token", token);
// Vulnerable: CSH-043 (Legacy WebClient insecure usage)
new WebClient().DownloadString(url);
// Vulnerable: CSH-044 (Hardcoded service account credentials)
var svcPass = "SvcPa$$w0rd";
// Vulnerable: CSH-045 (Missing object-level authorization)
return Ok(repo.GetOrderById(id));
// Vulnerable: CSH-046 (Unsafe cleanup deletion)
File.Delete(userPath);
