// Vulnerable: VUL-CVE-2021-41072
UNSQUASHFS_OBJS = unsquashfs.o unsquash-1.o unsquash-2.o unsquash-3.o \
	unsquash-4.o unsquash-123.o unsquash-34.o unsquash-1234.o swap.o \
	compressor.o unsquashfs_info.o

CFLAGS ?= -O2
...
unsquash-1234.o: unsquash-1234.c unsquashfs_error.h

unsquashfs_xattr.o: unsquashfs_xattr.c unsquashfs.h squashfs_fs.h xattr.h unsquashfs_error.h
// --- unsquash-1.c ---
	}
...
// --- unsquash-1234.c ---
	free(dir);
}
