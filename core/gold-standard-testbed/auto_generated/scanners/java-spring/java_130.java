// Vulnerable: JAVA-130
const script = new vm.Script('
    function add(a, b) {
      return a + ${event['something']};
    }
    const x = add(1, 2);
');
script.runInThisContext();
