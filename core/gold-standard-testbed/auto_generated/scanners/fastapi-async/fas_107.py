# Vulnerable: FAS-107
Entry.objects.all().filter().order_by('foo')[0]
