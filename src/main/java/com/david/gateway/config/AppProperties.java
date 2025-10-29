package com.david.gateway.config;

import com.david.core.forward.AppConvention;

import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

@Setter
@Getter
@Validated
@ConfigurationProperties(prefix = "app")
public class AppProperties extends AppConvention {

    private List<String> whiteListPaths = DEFAULT_WHITE_LIST_PATHS;

    /** 注意：此类沿用“根级”的 allowedOrigins 命名，不改变外部配置路径 */
    private List<String> allowedOrigins = DEFAULT_ALLOWED_ORIGINS;

    private Duration tokenCacheTtl = DEFAULT_TOKEN_CACHE_TTL;

    public void setAllowedOrigins(List<String> allowedOrigins) {
        this.allowedOrigins = normalizeList(allowedOrigins);
    }

    public void setTokenCacheTtl(Duration tokenCacheTtl) {
        this.tokenCacheTtl = normalizeDuration(tokenCacheTtl);
    }
}
