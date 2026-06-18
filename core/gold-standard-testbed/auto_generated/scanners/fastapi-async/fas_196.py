# Vulnerable: FAS-196
os.chmod(file_, st.st_mode | 0o111)
return file_
