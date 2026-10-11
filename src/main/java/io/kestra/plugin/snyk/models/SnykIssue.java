package io.kestra.plugin.snyk.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SnykIssue(String id, String type, SnykIssueAttributes attributes) {
}
