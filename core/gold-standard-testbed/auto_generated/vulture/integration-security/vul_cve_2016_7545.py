# Vulnerable: VUL-CVE-2016-7545
return subprocess.Popen(cmds).wait()

    selinux.setexeccon(self.__execcon)
    rc = subprocess.Popen(self.__cmds).wait()
    selinux.setexeccon(None)
    return rc

finally:
