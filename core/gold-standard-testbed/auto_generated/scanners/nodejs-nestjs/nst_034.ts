// Vulnerable: NST-034
const el = <MyCustomComponent {...props} some_other_prop={some_other_prop} />;
    return el;
}
function Test2(props, otherProps) {
    const {src, alt} = props;
    const {one_prop, two_prop} = otherProps;
