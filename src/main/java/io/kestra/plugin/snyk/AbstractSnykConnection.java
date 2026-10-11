package io.kestra.plugin.snyk;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import io.kestra.core.http.HttpRequest;
import io.kestra.core.http.HttpResponse;
import io.kestra.core.http.client.HttpClient;
import io.kestra.core.http.client.HttpClientResponseException;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractSnykConnection extends Task {
    public static final String DEFAULT_BASE_URL = "https://api.snyk.io/rest";
    public static final String DEFAULT_API_VERSION = "2024-10-15";

    @Schema(title = "Snyk API token", description = "API token used to authenticate against the Snyk REST API.")
    @NotNull
    @PluginProperty(secret = true, group = "connection")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    protected Property<String> token;

    @Schema(title = "Snyk REST API base URL", description = "Base URL for the Snyk REST API. Defaults to https://api.snyk.io/rest.")
    @NotNull
    @lombok.Builder.Default
    @PluginProperty(group = "connection")
    protected Property<String> baseUrl = Property.ofValue(DEFAULT_BASE_URL);

    @Schema(title = "Snyk REST API version", description = "API version sent as the version query parameter. The task property is named apiVersion because version is reserved by Kestra.")
    @NotNull
    @lombok.Builder.Default
    @PluginProperty(group = "connection")
    protected Property<String> apiVersion = Property.ofValue(DEFAULT_API_VERSION);

    protected String renderToken(RunContext runContext) throws Exception {
        return runContext.render(this.token).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("token is required"));
    }

    protected String renderBaseUrl(RunContext runContext) throws Exception {
        return stripTrailingSlash(runContext.render(this.baseUrl).as(String.class).orElse(DEFAULT_BASE_URL));
    }

    protected String renderApiVersion(RunContext runContext) throws Exception {
        return runContext.render(this.apiVersion).as(String.class).orElse(DEFAULT_API_VERSION);
    }

    protected HttpResponse<String> get(RunContext runContext, String uri) throws Exception {
        var request = HttpRequest.builder()
            .method("GET")
            .uri(URI.create(uri))
            .addHeader("Authorization", "token " + renderToken(runContext))
            .addHeader("Content-Type", "application/vnd.api+json")
            .addHeader("Accept", "application/vnd.api+json")
            .build();

        try (var client = new HttpClient(runContext, null)) {
            return client.request(request, String.class);
        } catch (HttpClientResponseException e) {
            throw rewriteException(e);
        }
    }

    private static HttpClientResponseException rewriteException(HttpClientResponseException exception) {
        var response = exception.getResponse();
        var status = response != null && response.getStatus() != null ? response.getStatus().getCode() : -1;
        var detail = "";

        if (response != null) {
            var body = response.getBody();
            if (body instanceof byte[] bytes && bytes.length > 0) {
                detail = ": " + truncate(new String(bytes, StandardCharsets.UTF_8));
            } else if (body instanceof String text && !text.isBlank()) {
                detail = ": " + truncate(text);
            }
        }

        return new HttpClientResponseException("Snyk API request failed with HTTP " + status + detail, response, exception);
    }

    protected static String joinUrl(String baseUrl, String path) {
        return stripTrailingSlash(baseUrl) + "/" + stripLeadingSlash(path);
    }

    protected static String stripTrailingSlash(String value) {
        return value.replaceAll("/+$", "");
    }

    protected static String stripLeadingSlash(String value) {
        return value.replaceAll("^/+", "");
    }

    private static String truncate(String body) {
        return body.length() <= 4000 ? body : body.substring(0, 4000) + "...";
    }
}
