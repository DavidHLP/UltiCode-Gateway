package com.david.gateway.filter;

import lombok.extern.slf4j.Slf4j;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.Set;

@Slf4j
@Component
public class SensitiveActionHeaderFilter implements GlobalFilter, Ordered {

    private static final String SENSITIVE_HEADER = "X-Sensitive-Action-Token";
    private static final Set<HttpMethod> SENSITIVE_METHODS = Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE,
            HttpMethod.PATCH);
    private static final String[] SENSITIVE_PATHS = { "/api/admin/**", "/api/admin/judge/**" };

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * 过滤请求，检查敏感操作是否包含必要的验证头
     *
     * @param exchange ServerWebExchange对象，包含请求和响应信息
     * @param chain    GatewayFilterChain对象，用于继续过滤链
     * @return Mono<Void> 异步处理结果
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpMethod method = exchange.getRequest().getMethod();
        String path = exchange.getRequest().getPath().value();
        if (requiresSensitiveHeader(Optional.of(method), Optional.of(path))) {
            String header = exchange.getRequest().getHeaders().getFirst(SENSITIVE_HEADER);
            if (!StringUtils.hasText(header)) {
                log.warn("敏感操作缺少校验头，path={} method={}", path, method);
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
        }
        return chain.filter(exchange);
    }

    /**
     * 判断请求是否需要敏感操作验证头
     *
     * @param method 请求方法的Optional包装
     * @param path   请求路径的Optional包装
     * @return boolean 如果需要验证头返回true，否则返回false
     */
    private boolean requiresSensitiveHeader(Optional<HttpMethod> method, Optional<String> path) {
        return method.isPresent()
                && path.isPresent()
                && SENSITIVE_METHODS.contains(method.get())
                && matchesAnyPath(path.get());
    }

    /**
     * 检查路径是否匹配任何敏感路径模式
     *
     * @param path 请求路径
     * @return boolean 如果匹配任何敏感路径返回true，否则返回false
     */
    private boolean matchesAnyPath(String path) {
        for (String pattern : SENSITIVE_PATHS) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取过滤器的执行顺序
     *
     * @return int 过滤器执行顺序，值越小优先级越高
     */
    @Override
    public int getOrder() {
        return -150;
    }
}
