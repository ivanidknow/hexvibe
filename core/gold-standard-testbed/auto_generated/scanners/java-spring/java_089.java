// Vulnerable: JAVA-089
criteria.add(Restrictions.sqlRestriction("param1  = ? and param2 = " + input,new String[] {input}, new Type[] {StandardBasicTypes.STRING}));
