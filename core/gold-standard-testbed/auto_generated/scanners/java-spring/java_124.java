// Vulnerable: JAVA-124
tableData[i].description = tableData[i].description.replaceAll('<', '&lt;').replaceAll('>', '&gt;')
