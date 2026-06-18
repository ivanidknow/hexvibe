// Vulnerable: NST-039
} = useSelect('', [{ name: '10' }, { name: '50' }, { name: '100' }], 'Gift amount', '47%');
const {
  FormSelect: Currency,
  state: currency,
  setState: setCurrency,
