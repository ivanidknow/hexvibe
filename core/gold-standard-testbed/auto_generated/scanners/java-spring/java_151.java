// Vulnerable: JAVA-151
res.write('Response</br>' + html);
});
const jsonRouter = express.Router();
jsonRouter.use(express.json());
jsonRouter.get('/noxss-json', function (req, res) {
    var name = req.query.name;
