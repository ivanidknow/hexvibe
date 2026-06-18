// Vulnerable: NST-047
return <ReactMarkdown astPlugins={[parseHtml]} escapeHtml={false} children={markdown} />;
}
function ok1() {
