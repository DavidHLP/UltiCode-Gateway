package com.david.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** 限流过滤器，用于限制客户端请求频率 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitFilter implements GlobalFilter, Ordered {

    /** 时间窗口大小（毫秒），默认为60秒 */
    private static final long WINDOW_MILLIS = 60_000;

    /** 默认请求限制数量 */
    private static final int DEFAULT_LIMIT = 240;

    /** 不同路径的请求限制配置 */
    private static final Map<String, Integer> PATH_LIMITS =
            Map.of("/api/auth/login", 40, "/api/auth/register", 20, "/api/auth/refresh", 80);

    /** 存储各客户端IP对应的限流桶 */
    private final ConcurrentHashMap<String, RateBucket> rateBuckets = new ConcurrentHashMap<>();

    /**
     * 执行限流过滤逻辑
     *
     * @param exchange Spring WebFlux交换对象，包含请求和响应信息
     * @param chain 过滤器链，用于继续执行后续过滤器
     * @return 响应式结果Mono对象
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        Optional<String> clientIpOptional = Optional.ofNullable(resolveClientIp(request));
        if (clientIpOptional.isEmpty()) {
            return chain.filter(exchange);
        }
        String clientIp = clientIpOptional.get();
        int limit =
                PATH_LIMITS.entrySet().stream()
                        .filter(entry -> path.startsWith(entry.getKey()))
                        .map(Map.Entry::getValue)
                        .findFirst()
                        .orElse(DEFAULT_LIMIT);
        RateBucket bucket = rateBuckets.computeIfAbsent(clientIp, key -> new RateBucket());
        if (bucket.incrementAndCheck(limit)) {
            return chain.filter(exchange);
        }
        log.warn("触发限流，IP={}, path={}", clientIp, path);
        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        return exchange.getResponse().setComplete();
    }

    /**
     * 获取过滤器执行顺序
     *
     * @return 执行顺序值，值越小优先级越高
     */
    @Override
    public int getOrder() {
        return -200;
    }

    /**
     * 解析客户端真实IP地址
     *
     * @param request 服务器HTTP请求对象
     * @return 客户端IP地址，无法解析时返回null
     */
    private String resolveClientIp(ServerHttpRequest request) {
        HttpHeaders headers = request.getHeaders();
        String header = headers.getFirst("X-Forwarded-For");
        if (StringUtils.hasText(header)) {
            return header.split(",")[0].trim();
        }
        return Optional.ofNullable(request.getRemoteAddress())
                .map(InetSocketAddress::getAddress)
                .map(Objects::toString)
                .orElse(null);
    }

    /** 限流桶内部类，用于跟踪特定客户端在时间窗口内的请求次数 */
    private static final class RateBucket {
        /** 请求计数器 */
        private final AtomicInteger counter = new AtomicInteger(0);

        /** 时间窗口起始时间戳 */
        private volatile long windowStart = Instant.now().toEpochMilli();

        /**
         * 增加计数并检查是否超过限制
         *
         * @param limit 允许的最大请求数
         * @return true表示未超过限制，false表示已超过限制
         */
        boolean incrementAndCheck(int limit) {
            long now = Instant.now().toEpochMilli();
            if (now - windowStart > WINDOW_MILLIS) {
                windowStart = now;
                counter.set(0);
            }
            int current = counter.incrementAndGet();
            return current <= limit;
        }
    }
}
