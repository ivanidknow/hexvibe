// Vulnerable: JAVA-145
var pth = path.join(opts.path, data[i]);
        doSmth(pth);
    }
})
app.post('/ok-test1', function okTest1(req,res) {
    let data = ['one', 'two', 'three'];
    for (let x of data) {
