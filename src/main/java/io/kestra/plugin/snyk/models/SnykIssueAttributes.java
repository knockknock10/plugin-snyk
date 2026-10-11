package io.kestra.plugin.snyk.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SnykIssueAttributes(
    String title,
    String description,
    String key,
    @JsonProperty("effective_severity_level") String effectiveSeverityLevel,
    String status,
    String resolution,
    String type,
    String tool,
    Boolean ignored,
    @JsonProperty("created_at") String createdAt,
    @JsonProperty("updated_at") String updatedAt,
    JsonNode coordinates,
    List<JsonNode> problems,
    List<JsonNode> severities,
    JsonNode risk,
    @JsonProperty("exploit_details") JsonNode exploitDetails,
    JsonNode slots
) {
}
