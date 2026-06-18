// Vulnerable: JAVA-154
let data = Object.assign(defaultData, newData)
    doSmthWith(data)
    return res.send(func())
})
let okController = function (req, res) {
    const defaultData = {foo: {bar: true}}
