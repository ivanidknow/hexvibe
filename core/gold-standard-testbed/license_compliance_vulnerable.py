# Gold testbed: License Compliance (LIC) — dependency and license markers.

# Vulnerable: LIC-001 (AGPL-3.0 in package.json / requirements.txt)
# "license": "AGPL-3.0"
# AGPL-3.0

# Vulnerable: LIC-002 (SSPL in hosted/cloud services)
# SSPL
# "license": "SSPL"

# Vulnerable: LIC-003 (Unmaintained / deprecated library > 2 years)
# deprecated: true
# last_updated: "2021-01-01"

# Vulnerable: LIC-004 (Unknown license metadata)
# "license": "UNKNOWN"

# Vulnerable: LIC-005 (Untrusted package source)
# pip install --index-url https://pypi.org/simple -r requirements.txt
# npm config set registry https://registry.npmjs.org/

# Vulnerable: LIC-006 (Missing license gate in CI)
# build pipeline without syft/license policy stage

# Vulnerable: LIC-008 (Missing SBOM evidence)
# no sbom artifact generated

# Vulnerable: LIC-009 (Transitive copyleft via syft output)
# syft report includes AGPL/GPL transitive dependency

# Vulnerable: LIC-010 (Binary-embedded license risk)
# bundled .so/.dll without license metadata

# Vulnerable: LIC-011 (Paladin: NuGet / external DLL integrity)
# dotnet restore without packages.lock.json integrity gate

