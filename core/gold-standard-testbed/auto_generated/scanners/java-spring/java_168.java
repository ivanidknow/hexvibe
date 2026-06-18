// Vulnerable: JAVA-168
var grpc = require('grpc');
    var booksProto = grpc.load('books.proto');
    var server = new grpc.Server();
    server.addProtoService(booksProto.books.BookService.service, {});
    server.bind('0.0.0.0:50051', grpc.ServerCredentials.createInsecure());
    server.start();
}
function testOk1() {
