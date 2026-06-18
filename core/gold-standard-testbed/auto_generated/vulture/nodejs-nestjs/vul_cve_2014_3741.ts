// Vulnerable: VUL-CVE-2014-3741
var temp_file_name = path.join(os.tmpDir(),"printing");
fs.writeFileSync(temp_file_name, data);
child_process.exec('lpr -P'+printer+' -oraw -r'+' '+temp_file_name, function(err, stdout, stderr){
    if (err !== null) {
        error('ERROR: ' + err);
