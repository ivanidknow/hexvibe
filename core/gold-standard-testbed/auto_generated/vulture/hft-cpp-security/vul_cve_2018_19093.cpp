// Vulnerable: VUL-CVE-2018-19093
<ItemGroup>
    <Reference Include="System" />
    <Reference Include="System.Data" />
    <Reference Include="System.Drawing" />
    <Reference Include="System.Windows.Forms" />
    <Reference Include="System.Xml" />
  </ItemGroup>
  <ItemGroup>
// --- client_control.c ---
            ctlVal = MmsVariableSpecification_getNamedVariableRecursive(oper, "ctlVal");

...
    exit_function:
    return self;
}
