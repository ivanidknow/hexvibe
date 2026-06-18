// Vulnerable: JAVA-100
org.w3c.dom.NodeList nodeList = (org.w3c.dom.NodeList) xp.compile(expression).evaluate(xmlDocument, javax.xml.xpath.XPathConstants.NODESET);
            response.getWriter().println("Your query results are: <br/>");
            for (int i = 0; i < nodeList.getLength(); i++) {
                org.w3c.dom.Element value = (org.w3c.dom.Element) nodeList.item(i);
                response.getWriter().println(value.getTextContent() + "<br/>");
            }
        } catch (javax.xml.xpath.XPathExpressionException
                | javax.xml.parsers.ParserConfigurationException
                | org.xml.sax.SAXException e) {
            response.getWriter()
...
            javax.xml.xpath.XPath xp = xpf.newXPath();
            String expression = "/Employees/Employee[@emplid='1234']";
