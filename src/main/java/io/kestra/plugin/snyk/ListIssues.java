package io.kestra.plugin.snyk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.models.tasks.common.FetchOutput;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.FileSerde;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.plugin.snyk.models.SnykIssue;
import io.kestra.plugin.snyk.models.SnykIssuesResponse;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import reactor.core.publisher.Flux;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(title = "List Snyk issues", description = "Retrieves issues for a Snyk organization from the Snyk REST API, with optional severity filtering and cursor pagination.")
@Plugin(
    examples = {
        @Example(
            title = "List critical and high Snyk issues",
            full = true,
            code = """
                id: snyk_list_issues
                namespace: company.team

                tasks:
                  - id: list_issues
                    type: io.kestra.plugin.snyk.ListIssues
                    token: "{{ secret('SNYK_API_TOKEN') }}"
                    orgId: "{{ secret('SNYK_ORG_ID') }}"
                    severities:
                      - CRITICAL
                      - HIGH
                    fetchType: FETCH
                """
        ),
        @Example(
            title = "Store all Snyk issues in internal storage",
            full = true,
            code = """
                id: snyk_store_issues
                namespace: company.team

                tasks:
                  - id: list_issues
                    type: io.kestra.plugin.snyk.ListIssues
                    token: "{{ secret('SNYK_API_TOKEN') }}"
                    orgId: "{{ secret('SNYK_ORG_ID') }}"
                    fetchType: STORE
                """
        )
    }
)
public class ListIssues extends AbstractSnykConnection implements RunnableTask<FetchOutput> {
    private static final int PAGE_LIMIT = 100;
    private static final ObjectMapper MAPPER = JacksonMapper.ofJson();

    @Schema(title = "Snyk organization ID", description = "Identifier of the Snyk organization whose issues should be retrieved.")
    @NotNull
    @PluginProperty(group = "main")
    protected Property<String> orgId;

    @Schema(title = "Severity filters", description = "Optional effective severity levels to include. When empty, all severities are returned.")
    @Builder.Default
    @PluginProperty(group = "processing")
    protected Property<List<Severity>> severities = Property.ofValue(List.of());

    @Schema(title = "Fetch mode", description = "FETCH returns all issues, FETCH_ONE returns the first issue only, and STORE writes all issues to Kestra internal storage.")
    @Builder.Default
    @PluginProperty(group = "processing")
    protected Property<FetchType> fetchType = Property.ofValue(FetchType.FETCH);

    @Override
    public FetchOutput run(RunContext runContext) throws Exception {
        var rOrgId = runContext.render(this.orgId).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("orgId is required"));
        var rFetchType = runContext.render(this.fetchType).as(FetchType.class).orElse(FetchType.FETCH);
        var rSeverities = runContext.render(this.severities).asList(Severity.class);

        var limit = rFetchType == FetchType.FETCH_ONE ? 1 : PAGE_LIMIT;
        var uri = buildInitialUrl(runContext, rOrgId, rSeverities, limit);
        var issues = new ArrayList<Map<String, Object>>();

        while (uri != null) {
            var response = get(runContext, uri);
            var body = response.getBody();

            if (body == null || body.isBlank()) {
                throw new IllegalStateException("Snyk API returned HTTP 200 with an empty response body");
            }

            var parsed = MAPPER.readValue(body, SnykIssuesResponse.class);
            var page = parsed.data() == null ? List.<SnykIssue>of() : parsed.data();

            for (var issue : page) {
                issues.add(toMap(issue));
                if (rFetchType == FetchType.FETCH_ONE) {
                    break;
                }
            }

            if (rFetchType == FetchType.FETCH_ONE || page.isEmpty()) {
                uri = null;
            } else {
                uri = nextUrl(runContext, parsed);
            }
        }

        return output(runContext, rFetchType, issues);
    }

    private String buildInitialUrl(RunContext runContext, String orgId, List<Severity> severities, int limit) throws Exception {
        var base = joinUrl(renderBaseUrl(runContext), "orgs/" + encodePathSegment(orgId) + "/issues");
        var query = new StringJoiner("&");
        query.add("version=" + encodeQuery(renderApiVersion(runContext)));
        query.add("limit=" + limit);

        for (var severity : severities) {
            query.add("effective_severity_level%5B%5D=" + encodeQuery(severity.name().toLowerCase(Locale.ROOT)));
        }

        return base + "?" + query;
    }

    private String nextUrl(RunContext runContext, SnykIssuesResponse response) throws Exception {
        var next = response.links() == null ? null : response.links().next();
        if (next == null || next.isNull() || !next.isTextual()) {
            return null;
        }

        var value = next.asText();
        if (value == null || value.isBlank()) {
            return null;
        }

        var nextUri = URI.create(value);
        return nextUri.isAbsolute() ? nextUri.toString() : URI.create(renderBaseUrl(runContext)).resolve(nextUri).toString();
    }

    private FetchOutput output(RunContext runContext, FetchType fetchType, List<Map<String, Object>> issues) throws Exception {
        return switch (fetchType) {
            case FETCH_ONE -> FetchOutput.builder()
                .row(issues.isEmpty() ? null : issues.getFirst())
                .size((long) issues.size())
                .build();

            case FETCH -> FetchOutput.builder()
                .rows(new ArrayList<>(issues))
                .size((long) issues.size())
                .build();

            case STORE -> {
                var tempFile = runContext.workingDir().createTempFile(".ion").toFile();
                try (var writer = java.nio.file.Files.newBufferedWriter(tempFile.toPath(), StandardCharsets.UTF_8)) {
                    FileSerde.writeAll(writer, Flux.fromIterable(issues)).block();
                }

                yield FetchOutput.builder()
                    .uri(runContext.storage().putFile(tempFile))
                    .size((long) issues.size())
                    .build();
            }

            case NONE -> throw new IllegalArgumentException("fetchType=NONE is not supported by ListIssues");
        };
    }

    private static Map<String, Object> toMap(SnykIssue issue) {
        return MAPPER.convertValue(issue, new TypeReference<>() {});
    }

    private static String encodePathSegment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String encodeQuery(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
