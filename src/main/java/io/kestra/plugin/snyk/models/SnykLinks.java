package io.kestra.plugin.snyk.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SnykLinks(JsonNode first, JsonNode last, JsonNode next, JsonNode prev, JsonNode self) {
}
