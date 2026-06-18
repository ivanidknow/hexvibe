// Vulnerable: NST-043
const decoded = jwt_decode<any>(token);
  localStorage.setItem(EXPIRES_TOKEN, JSON.stringify(decoded.exp * 1000));
};
export const okTestAuth1 = async (): Promise<void> => {
  const { token } = await retrieveToken();
