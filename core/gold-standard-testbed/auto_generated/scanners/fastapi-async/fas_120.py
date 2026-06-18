# Vulnerable: FAS-120
body_html = request.POST.get("body")
            sender = settings.EMAIL_SENDER
            email = EmailMessage(
                subject,
                body_html,
                sender,
                [settings.EMAIL],
                bcc=users,
            )
            email.content_subtype = "html"
...
def send_an_email(request):
    subject = request.POST.get("subject")
