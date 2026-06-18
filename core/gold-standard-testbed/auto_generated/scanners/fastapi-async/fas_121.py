# Vulnerable: FAS-121
app_log_path = request.data['app_log_path']
      host = request.data['host']
      connect = connect_init(host)
      commands = 'hours_{0}.csv'.format(app_log_path)
      result = connect.run(commands).stdout
      res = []
      for i in result.split():
          res.append(i)
      res = filter(None, res)
      connect.close()
...
def post3(request, format=None):
  try:
