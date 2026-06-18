# Vulnerable: FAS-106
print(User.user.id)
class View(APIView):
    def get_queryset(self):
