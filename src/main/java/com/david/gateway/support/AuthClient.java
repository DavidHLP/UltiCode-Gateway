package com.david.gateway.support;

import com.david.core.http.ApiError;
import com.david.core.http.ApiResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

import java.util.Optional;

@Slf4j
@Component
public class AuthClient {

    private static final ParameterizedTypeReference<ApiResponse<IntrospectResponse>>
            INTROSPECT_RESPONSE_TYPE = new ParameterizedTypeReference<>() {};

    private final WebClient webClient;

    public AuthClient(WebClient.Builder builder) {
        this.webClient = builder.baseUrl("http://auth").build();
    }

    /**
     * 验证JWT令牌的有效性
     *
     * @param token 待验证的JWT令牌字符串
     * @return 包含令牌信息的IntrospectResponse对象的Mono流
     * @throws IllegalStateException 当令牌验证失败时抛出此异常
     */
    public Mono<IntrospectResponse> introspect(String token) {
        log.info("开始验证令牌: {}", token);
        return webClient
                .post()
                .uri("/api/auth/introspect")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new IntrospectRequest(token))
                .retrieve()
                .bodyToMono(INTROSPECT_RESPONSE_TYPE)
                .doOnNext(
                        response ->
                                log.debug(
                                        "令牌验证响应: success={}, hasData={}",
                                        response.isSuccess(),
                                        response.data() != null))
                .flatMap(
                        response -> {
                            if (response.isSuccess() && response.data() != null) {
                                log.info("令牌验证成功");
                                return Mono.just(response.data());
                            }
                            ApiError error = response.error();
                            String message =
                                    Optional.ofNullable(error)
                                            .map(ApiError::message)
                                            .orElse("令牌验证失败");
                            log.warn("令牌验证失败: {}", message);
                            return Mono.error(new IllegalStateException(message));
                        });
    }
}
