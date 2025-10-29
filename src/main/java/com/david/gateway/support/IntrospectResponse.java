package com.david.gateway.support;

import java.util.List;

public record IntrospectResponse(Long userId, String username, List<String> roles) {
}
