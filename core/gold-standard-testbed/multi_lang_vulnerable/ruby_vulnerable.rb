# Vulnerable: RUBY-001 (eval user expr)
result = eval(expr)
# Vulnerable: RUBY-002 (system user cmd)
system(cmd)
# Vulnerable: RUBY-003 (backticks user host)
out = `ping -c 1 #{host}`
# Vulnerable: RUBY-004 (constantize from params)
klass = params[:klass].constantize
# Vulnerable: RUBY-005 (send user method)
service.send(method)
# Vulnerable: RUBY-006 (ERB from user template)
ERB.new(tpl).result(binding)
# Vulnerable: RUBY-007 (dynamic ORDER BY)
User.order(order)
# Vulnerable: RUBY-008 (unsafe YAML load)
obj = YAML.load(blob)
# Vulnerable: RUBY-009 (mass assignment)
user.update(params[:user])
# Vulnerable: RUBY-010 (unsafe render path)
render file: params[:path]
# Vulnerable: RUBY-011 (YAML.load deserialization)
obj2 = YAML.load(params[:payload])
# Vulnerable: RUBY-012 (command injection via backticks)
out2 = `#{params[:cmd]}`
# Vulnerable: RUBY-013 (open redirect)
redirect_to params[:next]
# Vulnerable: RUBY-014 (insecure cookie flags)
cookies[:session] = token
# Vulnerable: RUBY-015 (hardcoded secret)
JWT_SECRET = "prod-secret-123"
# Vulnerable: RUBY-016 (weak digest)
Digest::MD5.hexdigest(password)
# Vulnerable: RUBY-017 (SSRF)
Net::HTTP.get(URI(params[:url]))
# Vulnerable: RUBY-018 (unsafe constantize)
klass2 = params[:klass].constantize
# Vulnerable: RUBY-019 (debug endpoint behavior)
env_dump = ENV.to_h.to_s
# Vulnerable: RUBY-020 (sensitive error leakage)
render json: { error: e.message, backtrace: e.backtrace }, status: 500
