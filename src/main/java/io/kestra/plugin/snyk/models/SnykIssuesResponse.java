package io.kestra.plugin.snyk.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SnykIssuesResponse(List<SnykIssue> data, SnykLinks links) {
}
