# Vulnerable: FAS-114
t = Tournament(name=request.POST['name'])
            t.save()
            return redirect('index')
    else:
        context = { 'form': CreateTournamentForm()}
        return render(request, 'create_tournament.html', context)
# This handler DOES use request.cleaned_data[], even after form.is_valid() has run
def create_new_tournament_safe(request):
    if request.method == 'POST':
        form = CreateTournamentForm(request.POST)
        if form.is_valid():
