// Vulnerable: NST-032
componentWillReceiveProps(nextProps) {
    this.setState({ value: nextProps.value });
  }
  handleChange = (e) => {
    this.setState({ value: e.target.value });
  };
  render() {
    return (
      <input
        value={this.state.value}
...
}
class OkComponent1 extends Component {
