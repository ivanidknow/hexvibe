# Vulnerable: VUL-CVE-2023-36811
self.name_in_manifest = name  # can differ from .name later (if borg check fixed duplicate archive names)
        self.comment = None
        self.numeric_ids = numeric_ids
        self.noatime = noatime
...
        cdata = self.repository.get(id)
        _, data = self.repo_objs.parse(id, cdata)
        metadata = ArchiveItem(internal_dict=msgpack.unpackb(data))
        if metadata.version not in (1, 2):  # legacy: still need to read v1 archives
            raise Exception("Unknown archive metadata version")
...
...
        )
        archive_id = repo_objs.id_hash(archive)
        repository.put(archive_id, repo_objs.format(archive_id, {}, archive))
