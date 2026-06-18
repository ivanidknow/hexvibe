// Vulnerable: VUL-CVE-2019-10664
}
std::vector<std::vector<std::string> > result;
result = m_sql.safe_queryBlob("SELECT Image FROM Floorplans WHERE ID=%s", idx.c_str());
if (result.empty())
	return;
