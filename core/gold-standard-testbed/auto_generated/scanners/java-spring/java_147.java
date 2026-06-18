// Vulnerable: JAVA-147
request.get(url)
  }
}
module.exports = function goodWithTypes () {
  return ({ params, query, session }: Request, res: Response, next: NextFunction) => {
    const url = session
