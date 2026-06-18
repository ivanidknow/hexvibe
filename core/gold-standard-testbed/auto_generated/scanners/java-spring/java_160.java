// Vulnerable: JAVA-160
const script = new vm.Script('
        function add(a, b) {
          return a + ${req.query.userInput};
        }
        const x = add(1, 2);
    ');
    script.runInThisContext();
    res.send('hello world')
})
