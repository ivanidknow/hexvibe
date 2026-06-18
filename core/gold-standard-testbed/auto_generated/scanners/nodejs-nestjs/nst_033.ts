// Vulnerable: NST-033
const [formattedText] = useState(() => slowlyFormatText(props.text))
  return <button>{formattedText}</button>
}
function OkTest1({ color, children }) {
  const textColor = useMemo(
