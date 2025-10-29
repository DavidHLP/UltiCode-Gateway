package com.david.gateway.filter;

import com.david.core.forward.ForwardedUser;
import com.david.core.forward.ForwardedUserHeaders;
import com.david.core.http.ApiError;
import com.david.core.http.ApiResponse;
import com.david.gateway.config.AppProperties;
import com.david.gateway.support.AuthClient;
import com.david.gateway.support.IntrospectResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * JWT认证过滤器，用于验证请求中的JWT令牌并设置用户信息到请求头中
 *
 * <p>该过滤器会检查请求路径是否在白名单中，如果不在白名单中则要求提供有效的JWT令牌。 成功验证后，将用户信息添加到请求头中供下游服务使用。
 */
@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final String SESSION_CACHE_KEY = "CF_GATEWAY_AUTH_CACHE";
    private final AuthClient authClient;
    private final AppProperties appProperties;
    private final ObjectMapper objectMapper;
    private final AntPathMatcher pathMatcher;
    private final long tokenCacheTtlMillis;

    /**
     * 构造函数
     *
     * @param authClient 认证客户端，用于调用认证服务
     * @param appProperties 应用配置属性
     * @param objectMapper JSON对象映射器
     * @param pathMatcher 路径匹配器
     */
    public JwtAuthenticationFilter(
            AuthClient authClient,
            AppProperties appProperties,
            ObjectMapper objectMapper,
            AntPathMatcher pathMatcher) {
        this.authClient = authClient;
        this.appProperties = appProperties;
        this.objectMapper = objectMapper;
        this.pathMatcher = pathMatcher;
        Duration ttl = appProperties.getTokenCacheTtl();
        this.tokenCacheTtlMillis = Optional.ofNullable(ttl).map(Duration::toMillis).orElse(0L);
    }

    /**
     * 过滤器核心方法，处理每个请求的认证逻辑
     *
     * @param exchange 服务器网络交换对象
     * @param chain 网关过滤器链
     * @return Mono<Void> 异步处理结果
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 跳过OPTIONS请求
        if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            log.debug("跳过路径 {} 的 OPTIONS 请求", exchange.getRequest().getPath().value());
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getPath().value();

        // 检查路径是否在白名单中
        if (isWhitelisted(path)) {
            log.debug("路径 {} 在白名单中，跳过认证", path);
            return chain.filter(exchange);
        }

        // 获取Authorization头
        String authorization =
                exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(authorization) || !authorization.startsWith("Bearer ")) {
            log.warn("路径 {} 缺少或无效的 Authorization 头", path);
            return respond(exchange, HttpStatus.UNAUTHORIZED, "缺少 Authorization 头");
        }

        String token = authorization.substring(7);
        log.debug("为路径 {} 验证令牌", path);

        // 使用会话缓存或调用认证服务验证令牌
        return exchange.getSession()
                .flatMap(
                        session -> {
                            CachedAuth cached = session.getAttribute(SESSION_CACHE_KEY);
                            if (cached != null && cached.matches(token) && !cached.isExpired()) {
                                log.trace("命中会话缓存，用户: {}", cached.payload().username());
                                return continueChainWithUser(chain, exchange, cached.payload());
                            }
                            return authClient
                                    .introspect(token)
                                    .flatMap(
                                            payload -> {
                                                log.debug(
                                                        "用户 {} 的令牌验证成功，角色：{}",
                                                        payload.username(),
                                                        payload.roles());
                                                if (tokenCacheTtlMillis > 0) {
                                                    session.getAttributes()
                                                            .put(
                                                                    SESSION_CACHE_KEY,
                                                                    CachedAuth.from(
                                                                            token,
                                                                            payload,
                                                                            tokenCacheTtlMillis));
                                                }
                                                return continueChainWithUser(
                                                        chain, exchange, payload);
                                            });
                        })
                .onErrorResume(
                        WebClientResponseException.class,
                        ex -> {
                            if (ex.getStatusCode().is4xxClientError()) {
                                log.warn("令牌验证期间客户端错误：{}", ex.getMessage());
                                return respond(exchange, HttpStatus.UNAUTHORIZED, "令牌无效或已过期");
                            }
                            log.error("令牌验证期间服务器错误", ex);
                            return respond(exchange, HttpStatus.SERVICE_UNAVAILABLE, "认证服务不可用");
                        })
                .onErrorResume(
                        ex -> {
                            if (ex instanceof IllegalStateException illegalStateException) {
                                String failureMessage =
                                        StringUtils.hasText(illegalStateException.getMessage())
                                                ? illegalStateException.getMessage()
                                                : "令牌无效或已过期";
                                log.warn("令牌处理期间非法状态：{}", failureMessage);
                                return respond(exchange, HttpStatus.UNAUTHORIZED, failureMessage);
                            }
                            log.error("认证期间发生意外错误", ex);
                            return respond(exchange, HttpStatus.SERVICE_UNAVAILABLE, "认证服务不可用");
                        });
    }

    /**
     * 返回过滤器排序值，数值越小优先级越高
     *
     * @return 排序值
     */
    @Override
    public int getOrder() {
        return -100;
    }

    /**
     * 检查给定路径是否在白名单中
     *
     * @param path 请求路径
     * @return 如果路径在白名单中返回true，否则返回false
     */
    private boolean isWhitelisted(String path) {
        List<String> whitelist = appProperties.getWhiteListPaths();
        boolean result =
                Optional.ofNullable(whitelist).stream()
                        .flatMap(List::stream)
                        .anyMatch(pattern -> pathMatcher.match(pattern, path));
        if (result) {
            log.trace("路径 {} 匹配白名单模式", path);
        }
        return result;
    }

    /**
     * 继续执行过滤器链，将认证用户信息添加到请求头中
     *
     * @param chain 网关过滤器链
     * @param exchange 服务器网络交换对象
     * @param payload 认证响应数据
     * @return Mono<Void> 异步处理结果
     */
    private Mono<Void> continueChainWithUser(
            GatewayFilterChain chain, ServerWebExchange exchange, IntrospectResponse payload) {
        // 验证用户ID是否存在
        if (payload.userId() == null) {
            log.warn("令牌验证成功但缺少用户ID，拒绝请求");
            return respond(exchange, HttpStatus.UNAUTHORIZED, "认证信息不完整，缺少用户ID");
        }

        // 验证用户名是否存在
        if (!StringUtils.hasText(payload.username())) {
            log.warn("令牌验证成功但缺少用户名，拒绝请求");
            return respond(exchange, HttpStatus.UNAUTHORIZED, "认证信息不完整，缺少用户名");
        }

        // 创建转发用户对象并应用到请求头
        ForwardedUser forwardedUser =
                ForwardedUser.of(payload.userId(), payload.username(), payload.roles());
        ServerHttpRequest mutatedRequest =
                exchange.getRequest()
                        .mutate()
                        .headers(headers -> applyForwardedUser(headers, forwardedUser))
                        .build();
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    /**
     * 将认证用户信息应用到HTTP请求头中
     *
     * @param headers HTTP请求头
     * @param user 转发用户信息
     */
    private void applyForwardedUser(HttpHeaders headers, ForwardedUser user) {
        // 设置用户ID头
        if (user.id() != null) {
            headers.set(ForwardedUserHeaders.USER_ID, String.valueOf(user.id()));
        } else {
            headers.remove(ForwardedUserHeaders.USER_ID);
        }

        // 设置用户名头
        String username = user.username();
        headers.set(ForwardedUserHeaders.USER_NAME, Optional.ofNullable(username).orElse(""));

        // 设置用户角色头
        String roles =
                String.join(
                        ForwardedUserHeaders.ROLE_DELIMITER,
                        Optional.ofNullable(user.roles()).orElse(List.of()));
        headers.set(ForwardedUserHeaders.USER_ROLES, roles);
        log.debug("为用户 {} 应用转发用户头，ID：{}，角色：{}", username, user.id(), roles);
    }

    /**
     * 向客户端发送错误响应
     *
     * @param exchange 服务器网络交换对象
     * @param status HTTP状态码
     * @param message 错误消息
     * @return Mono<Void> 异步处理结果
     */
    private Mono<Void> respond(ServerWebExchange exchange, HttpStatus status, String message) {
        log.debug("响应状态：{}，消息：{}", status, message);
        ApiResponse<Void> errorResponse =
                ApiResponse.failure(ApiError.of(status.value(), status.name(), message));
        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(errorResponse);
        } catch (Exception ex) {
            log.warn("序列化错误响应失败，使用备用方案", ex);
            bytes =
                    ("{\"status\":" + status.value() + ",\"message\":\"" + message + "\"}")
                            .getBytes(StandardCharsets.UTF_8);
        }
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse()
                .getHeaders()
                .set(HttpHeaders.CONTENT_TYPE, "application/json;charset=UTF-8");
        return exchange.getResponse()
                .writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }

    /** 缓存的认证信息记录类 */
    private record CachedAuth(String token, IntrospectResponse payload, long expiresAt) {
        /**
         * 创建缓存认证信息实例
         *
         * @param token JWT令牌
         * @param payload 认证响应数据
         * @param ttlMillis 缓存有效期（毫秒）
         * @return CachedAuth 缓存认证信息实例
         */
        private static CachedAuth from(String token, IntrospectResponse payload, long ttlMillis) {
            long effectiveTtl = Math.max(ttlMillis, 0);
            long expiresAt = System.currentTimeMillis() + effectiveTtl;
            return new CachedAuth(token, payload, expiresAt);
        }

        /**
         * 检查令牌是否匹配
         *
         * @param rawToken 原始令牌
         * @return 如果令牌匹配返回true，否则返回false
         */
        private boolean matches(String rawToken) {
            return Objects.equals(this.token, rawToken);
        }

        /**
         * 检查缓存是否过期
         *
         * @return 如果缓存过期返回true，否则返回false
         */
        private boolean isExpired() {
            return System.currentTimeMillis() >= expiresAt;
        }
    }
}
