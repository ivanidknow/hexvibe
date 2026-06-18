// Vulnerable: CSH-059
searcher.Filter = String.Format("({0}={1})", SAMAccountNameAttribute, userName);
            searcher.PropertiesToLoad.Add(DisplayNameAttribute);
            searcher.PropertiesToLoad.Add(SAMAccountNameAttribute);
            var result = searcher.FindOne();
            if (result != null)
            {
                var displayName = result.Properties[DisplayNameAttribute];
                var samAccountName = result.Properties[SAMAccountNameAttribute];
                return new User
                {
...
        using (DirectorySearcher searcher = new DirectorySearcher(entry))
        {
