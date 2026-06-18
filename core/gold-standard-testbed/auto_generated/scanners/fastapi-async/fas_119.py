# Vulnerable: FAS-119
writer.writerow(title_row)
    writer.writerows(data)
    stream.flush()
    stream.seek(0)
    return stream.read()
@app.route("ok")
def ok():
    with open("data.csv") as fin:
