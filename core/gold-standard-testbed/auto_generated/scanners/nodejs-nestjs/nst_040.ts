// Vulnerable: NST-040
let params = {smth: 'test123', dangerouslySetInnerHTML: {__html: foo.bar},a:b};
    return React.createElement('div', params);
}
