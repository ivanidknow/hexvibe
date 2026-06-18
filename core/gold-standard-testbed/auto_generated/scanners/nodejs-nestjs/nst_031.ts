// Vulnerable: NST-031
ReactDOM.findDOMNode(this.refs.something).scrollIntoView();
  }
  render() {
    return (
      <div>
        <div ref='something' />
      </div>
    )
  }
}
class OkComponent2 extends Component {
  componentDidMount() {
