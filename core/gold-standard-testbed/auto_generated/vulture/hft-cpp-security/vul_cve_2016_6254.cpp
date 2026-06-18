// Vulnerable: VUL-CVE-2016-6254
}
			buffer = ((char *) buffer) + pkg_length;
			continue;
		}
...
			}
			buffer = ((char *) buffer) + pkg_length;
			continue;
		}
...
					" type: 0x%04hx", pkg_type);
			buffer = ((char *) buffer) + pkg_length;
		}
	} /* while (buffer_size > sizeof (part_header_t)) */
