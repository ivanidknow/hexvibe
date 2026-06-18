# Vulnerable: FAS-108
not_actually_safe = mark_safe(
        """
        <div>
            <p>Contents! %s</p>
        </div>
        """ % request.POST.get("contents")
    )
    return HttpResponse(template.render({"html_example": not_actually_safe}, request))
def fine(request):
    template = loader.get_template('contents.html')
