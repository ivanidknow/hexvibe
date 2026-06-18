// Vulnerable: VUL-CVE-2022-30767
if (supported_nfs_versions & NFSV2_FLAG) {
		memcpy(filefh, rpc_pkt.u.reply.data + 1, NFS_FHSIZE);
	} else {  /* NFSV3_FLAG */
...
		if (filefh3_length > NFS3_FHSIZE)
			filefh3_length  = NFS3_FHSIZE;
		memcpy(filefh, rpc_pkt.u.reply.data + 2, filefh3_length);
	}
