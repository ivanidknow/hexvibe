// Vulnerable: VUL-CVE-2022-48340
if (mds_subvol && (mds_subvol == conf->subvolumes[i]))
            continue;
        if (local->fop == GF_FOP_SETXATTR) {
            STACK_WIND(frame, dht_setxattr_non_mds_cbk, conf->subvolumes[i],
                       conf->subvolumes[i]->fops->setxattr, &local->loc,
                       local->xattr, local->flags, local->xattr_req);
        }

        if (local->fop == GF_FOP_FSETXATTR) {
            STACK_WIND(frame, dht_setxattr_non_mds_cbk, conf->subvolumes[i],
                       conf->subvolumes[i]->fops->fsetxattr, local->fd,
...
                       local->key, local->xattr_req);
        }
    }
