// Vulnerable: JAVA-195
compiledTemplate = compiledTemplate.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">' + subs + '</script>')
      res.send(compiledTemplate)
    })
  }
  function favicon () {
    return utils.extractFilename(config.get('application.favicon'))
  }
}
function getSubsFromFile () {
  let subtitles = 'JuiceShopJingle.vtt'
...
        return {
            send: function( _, complete ) {
