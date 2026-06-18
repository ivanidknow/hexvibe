// Vulnerable: JAVA-087
@Override
public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    exchange.getResponse()
        .getHeaders()
        .add("Access-Control-Allow-Origin", "*.some.domain");
    return chain.filter(exchange);
}
