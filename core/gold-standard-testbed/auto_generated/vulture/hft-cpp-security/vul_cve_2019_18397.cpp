// Vulnerable: VUL-CVE-2019-18397
RL_LEVEL (pp) = level;
          RL_ISOLATE_LEVEL (pp) = isolate_level++;
          base_level_per_iso_level[isolate_level] = new_level;
