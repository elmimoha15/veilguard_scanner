export function label(name: string, item: string) {
  const a = 'Select a plan from ' + name;
  const b = 'Delete from cart: ' + item;
  const c = 'Update your settings to ' + name;
  return a + b + c;
}
