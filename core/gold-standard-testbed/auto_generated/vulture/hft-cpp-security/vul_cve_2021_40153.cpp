// Vulnerable: VUL-CVE-2021-40153
UNSQUASHFS_OBJS = unsquashfs.o unsquash-1.o unsquash-2.o unsquash-3.o \
	unsquash-4.o unsquash-123.o unsquash-34.o swap.o compressor.o unsquashfs_info.o

CFLAGS ?= -O2
...
unsquash-34.o: unsquashfs.h unsquash-34.c

unsquashfs_xattr.o: unsquashfs_xattr.c unsquashfs.h squashfs_fs.h xattr.h
// --- unsquash-1.c ---
 * filesystem.
 *
...
			dire->name[dire->size + 1] = '\0';
			TRACE("squashfs_opendir: directory entry %s, inode "
				"%d:%d, type %d\n", dire->name,
