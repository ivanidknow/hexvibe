# Vulnerable: RUB-007
s = Net::SSH::Telnet.new(
        "Dump_log" => "/dev/stdout",
        "Session" => ssh
  )
  puts "Logged in"
  p s.cmd("echo hello")
end
def ok1
