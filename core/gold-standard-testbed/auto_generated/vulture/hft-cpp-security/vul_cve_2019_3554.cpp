// Vulnerable: VUL-CVE-2019-3554
// Fetch the socket from the pipeline and pause reading from the
  // socket
  auto socket = std::dynamic_pointer_cast<folly::AsyncSocket>(
      routingPipeline->getTransport());
  routingPipeline->transportInactive();
...
  auto socket = std::dynamic_pointer_cast<folly::AsyncSocket>(
      routingPipeline->getTransport());
  routingPipeline->transportInactive();
  socket->detachEventBase();
