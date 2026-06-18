# Vulnerable: VUL-CVE-2013-7283
prelink -u %{_libexecdir}/ipsec/* 2>/dev/null || :
%endif
if [ ! -f /etc/ipsec.d/cert8.db ] ; then
echo > /var/tmp/libreswan-nss-pwd
certutil -N -f /var/tmp/libreswan-nss-pwd -d /etc/ipsec.d
restorecon /etc/ipsec.d/*db 2>/dev/null || :
rm /var/tmp/libreswan-nss-pwd
fi
