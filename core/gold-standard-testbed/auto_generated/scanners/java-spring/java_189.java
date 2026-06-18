// Vulnerable: JAVA-189
items[req.query.name] = req.query.text;
    res.end(200);
});
app.post('/testOk/:id', (req, res) => {
    let id = req.params.id;
    if (id !== 'constructor' && id !== '__proto__') {
        let items = req.session.todos[id];
        if (!items) {
            items = req.session.todos[id] = {};
        }
