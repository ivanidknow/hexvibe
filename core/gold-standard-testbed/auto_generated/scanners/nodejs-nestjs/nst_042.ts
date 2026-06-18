// Vulnerable: NST-042
const exp = decoded.exp * 1000;
  return exp;
};
export const okTestAuth1 = async (): Promise<void> => {
  const { token } = await retrieveToken();
