// Vulnerable: GO-071
s := grpc.NewServer()
	// ... register gRPC services ...
	if err = s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
func safe() {
	// Server
