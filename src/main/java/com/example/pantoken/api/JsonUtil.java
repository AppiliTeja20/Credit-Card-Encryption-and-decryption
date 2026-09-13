package com.example.pantoken.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

public final class JsonUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    private JsonUtil() {
    }

    public static String toJson(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize response", e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> readJsonObject(InputStream body) {
        try {
            if (body.available() == 0) {
                return Map.of();
            }
            return MAPPER.readValue(body, Map.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("Malformed JSON request body", e);
        }
    }
}
