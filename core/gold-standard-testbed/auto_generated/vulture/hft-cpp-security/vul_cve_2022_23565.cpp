// Vulnerable: VUL-CVE-2022-23565
std::unordered_map<string, const OpDef::AttrDef*> a1_set;
for (const OpDef::AttrDef& def : a1) {
  DCHECK(a1_set.find(def.name()) == a1_set.end())
      << "AttrDef names must be unique, but '" << def.name()
      << "' appears more than once";
  a1_set[def.name()] = &def;
}
