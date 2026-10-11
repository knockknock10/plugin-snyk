package io.kestra.plugin.snyk;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.http.client.HttpClientResponseException;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.core.utils.TestsUtils;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

@KestraTest
@WireMockTest
class ListIssuesTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void fetchesAllPagesAndAppliesSeverityFilter(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/rest/orgs/org-123/issues"))
            .withQueryParam("version", equalTo("2024-10-15"))
            .withQueryParam("limit", equalTo("100"))
            .withQueryParam("effective_severity_level[]", equalTo("critical"))
            .withQueryParam("effective_severity_level[]", equalTo("high"))
            .willReturn(okJson("""
                {
                  "data": [
                    {
                      "id": "issue-1",
                      "type": "issue",
                      "attributes": {
                        "title": "First issue",
                        "effective_severity_level": "critical",
                        "status": "open"
                      }
                    }
                  ],
                  "links": {
                    "next": "/rest/orgs/org-123/issues?version=2024-10-15&limit=100&starting_after=cursor-1"
                  }
                }
                """)));

        stubFor(get(urlPathEqualTo("/rest/orgs/org-123/issues"))
            .withQueryParam("starting_after", equalTo("cursor-1"))
            .willReturn(okJson("""
                {
                  "data": [
                    {
                      "id": "issue-2",
                      "type": "issue",
                      "attributes": {
                        "title": "Second issue",
                        "effective_severity_level": "high",
                        "status": "open"
                      }
                    }
                  ],
                  "links": {}
                }
                """)));

        var task = ListIssues.builder()
            .id(IdUtils.create())
            .type(ListIssues.class.getName())
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue(wireMock.getHttpBaseUrl() + "/rest"))
            .orgId(Property.ofValue("org-123"))
            .severities(Property.ofValue(List.of(Severity.CRITICAL, Severity.HIGH)))
            .fetchType(Property.ofValue(FetchType.FETCH))
            .build();

        var output = task.run(TestsUtils.mockRunContext(runContextFactory, task, Map.of()));

        assertThat(output.getSize(), is(2L));
        assertThat(output.getRows(), hasSize(2));
        assertThat(output.getRows().getFirst().toString(), containsString("issue-1"));
        assertThat(output.getRows().get(1).toString(), containsString("issue-2"));
        verify(1, get(urlPathEqualTo("/rest/orgs/org-123/issues"))
            .withQueryParam("starting_after", equalTo("cursor-1")));
    }

    @Test
    void fetchOneDoesNotFollowPagination(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/rest/orgs/org-123/issues"))
            .withQueryParam("limit", equalTo("1"))
            .willReturn(okJson("""
                {
                  "data": [
                    {
                      "id": "issue-1",
                      "type": "issue",
                      "attributes": {
                        "title": "First issue"
                      }
                    }
                  ],
                  "links": {
                    "next": "/rest/orgs/org-123/issues?starting_after=never-needed"
                  }
                }
                """)));

        var task = ListIssues.builder()
            .id(IdUtils.create())
            .type(ListIssues.class.getName())
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue(wireMock.getHttpBaseUrl() + "/rest"))
            .orgId(Property.ofValue("org-123"))
            .fetchType(Property.ofValue(FetchType.FETCH_ONE))
            .build();

        var output = task.run(TestsUtils.mockRunContext(runContextFactory, task, Map.of()));

        assertThat(output.getSize(), is(1L));
        assertThat(output.getRow().get("id"), is("issue-1"));
        verify(1, get(urlPathEqualTo("/rest/orgs/org-123/issues")));
    }

    @Test
    void storesIssuesInKestraStorage(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/rest/orgs/org-123/issues"))
            .willReturn(okJson("""
                {
                  "data": [
                    {
                      "id": "issue-1",
                      "type": "issue",
                      "attributes": {
                        "title": "First issue"
                      }
                    }
                  ],
                  "links": {}
                }
                """)));

        var task = ListIssues.builder()
            .id(IdUtils.create())
            .type(ListIssues.class.getName())
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue(wireMock.getHttpBaseUrl() + "/rest"))
            .orgId(Property.ofValue("org-123"))
            .fetchType(Property.ofValue(FetchType.STORE))
            .build();

        var output = task.run(TestsUtils.mockRunContext(runContextFactory, task, Map.of()));

        assertThat(output.getSize(), is(1L));
        assertThat(output.getRows(), org.hamcrest.Matchers.nullValue());
        assertThat(output.getUri(), notNullValue());
    }

    @Test
    void emptyResponseIsSuccessful(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/rest/orgs/org-123/issues"))
            .willReturn(okJson("""
                {
                  "data": [],
                  "links": {}
                }
                """)));

        var task = ListIssues.builder()
            .id(IdUtils.create())
            .type(ListIssues.class.getName())
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue(wireMock.getHttpBaseUrl() + "/rest"))
            .orgId(Property.ofValue("org-123"))
            .build();

        var output = task.run(TestsUtils.mockRunContext(runContextFactory, task, Map.of()));

        assertThat(output.getSize(), is(0L));
        assertThat(output.getRows(), hasSize(0));
    }

    @Test
    void surfacesHttpErrorsWithoutLeakingToken(WireMockRuntimeInfo wireMock) {
        stubFor(get(urlPathEqualTo("/rest/orgs/org-123/issues"))
            .willReturn(aResponse()
                .withStatus(401)
                .withHeader("Content-Type", "application/vnd.api+json")
                .withBody("{\"errors\":[{\"detail\":\"invalid token\"}]}")));

        var secret = "super-secret-token";
        var task = ListIssues.builder()
            .id(IdUtils.create())
            .type(ListIssues.class.getName())
            .token(Property.ofValue(secret))
            .baseUrl(Property.ofValue(wireMock.getHttpBaseUrl() + "/rest"))
            .orgId(Property.ofValue("org-123"))
            .build();

        var exception = assertThrows(
            HttpClientResponseException.class,
            () -> task.run(TestsUtils.mockRunContext(runContextFactory, task, Map.of()))
        );

        assertThat(exception.getMessage(), containsString("HTTP 401"));
        assertThat(exception.getMessage(), containsString("invalid token"));
        assertThat(exception.getMessage(), not(containsString(secret)));
        assertThat(task.toString(), not(containsString(secret)));
    }
}
