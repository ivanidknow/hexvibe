# Vulnerable: FAS-146
return render_template('/markup-unescape.html', query=mkup(search_query), playlist=playlist)
@app.route('/good')
def good_test():
    search_query = request.args.get('q')
