package com.david.gateway.config;

import java.time.Duration;
import java.util.List;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class GatewayConfiguration {

  /**
   * 创建并配置CorsWebFilter bean，用于处理跨域请求
   *
   * @param appProperties 应用配置属性，包含允许的源列表
   * @return 配置好的CorsWebFilter实例
   */
  @Bean
  public CorsWebFilter corsWebFilter(AppProperties appProperties) {
    CorsConfiguration corsConfiguration = new CorsConfiguration();
    List<String> allowedOrigins = appProperties.getAllowedOrigins();
    if (!CollectionUtils.isEmpty(allowedOrigins)) {
      if (allowedOrigins.stream().anyMatch(origin -> origin.contains("*"))) {
        corsConfiguration.setAllowedOriginPatterns(allowedOrigins);
      } else {
        corsConfiguration.setAllowedOrigins(allowedOrigins);
      }
    } else {
      corsConfiguration.setAllowedOriginPatterns(
          List.of("http://localhost:5173", "http://localhost:5174"));
    }
    corsConfiguration.setAllowedMethods(
        List.of(
            HttpMethod.GET.name(),
            HttpMethod.POST.name(),
            HttpMethod.PUT.name(),
            HttpMethod.DELETE.name(),
            HttpMethod.OPTIONS.name()));
    corsConfiguration.setAllowedHeaders(List.of("*"));
    corsConfiguration.setExposedHeaders(List.of("Authorization", "Set-Cookie"));
    corsConfiguration.setAllowCredentials(true);
    corsConfiguration.setMaxAge(Duration.ofHours(1));

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", corsConfiguration);
    return new CorsWebFilter(source);
  }

  /**
   * 创建带负载均衡功能的WebClient.Builder bean
   *
   * @return 配置了负载均衡功能的WebClient.Builder实例
   */
  @Bean
  @LoadBalanced
  public WebClient.Builder loadBalancedWebClientBuilder() {
    return WebClient.builder();
  }

  /**
   * 创建AntPathMatcher bean，用于路径匹配
   *
   * @return AntPathMatcher实例
   */
  @Bean
  public AntPathMatcher antPathMatcher() {
    return new AntPathMatcher();
  }
}
