"""Unit tests for JSASTAnalyzer using real-world JavaScript samples.

Sources: GitHub gists, open-source repos, and real-world code patterns.
Each test case is annotated with the original source.
"""

from __future__ import annotations

import pytest

from prowl.modules.s4_js_analysis import JSASTAnalyzer, JSEndpoint


@pytest.fixture(scope="module")
def analyzer() -> JSASTAnalyzer:
    return JSASTAnalyzer()


# ======================================================================
# Helper
# ======================================================================

def urls(eps: list[JSEndpoint]) -> set[str]:
    return {e.url for e in eps}


def methods(eps: list[JSEndpoint]) -> dict[str, str]:
    return {e.url: e.method for e in eps}


def params_for(eps: list[JSEndpoint], url: str) -> list[str]:
    for e in eps:
        if e.url == url:
            return [p.name for p in e.parameters]
    return []


def tags_for(eps: list[JSEndpoint], url: str) -> list[str]:
    for e in eps:
        if e.url == url:
            return e.tags
    return []


# ======================================================================
# 1. fetch() API
# ======================================================================


class TestFetch:
    """Real-world fetch() patterns from GitHub gists."""

    def test_fetch_simple_get(self, analyzer: JSASTAnalyzer):
        """Source: justsml/fetch-api-examples"""
        js = """
        fetch('https://api.github.com/orgs/nodejs')
            .then(response => response.json())
            .then(data => console.log(data));
        """
        eps = analyzer.analyze(js)
        assert "https://api.github.com/orgs/nodejs" in urls(eps)

    def test_fetch_post_with_json_body(self, analyzer: JSASTAnalyzer):
        """Source: justsml/fetch-api-examples"""
        js = """
        fetch('/api/endpoint', {
            method: 'POST',
            body: JSON.stringify({name: 'test', email: 'a@b.com'}),
            headers: {
                'Content-Type': 'application/json'
            }
        });
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/endpoint"]
        assert len(found) >= 1
        assert found[0].method == "POST"

    def test_fetch_with_credentials(self, analyzer: JSASTAnalyzer):
        """Source: justsml/fetch-api-examples"""
        js = """
        fetch('https://api.github.com/orgs/nodejs', {
            credentials: 'include'
        })
        .then(response => response.json());
        """
        eps = analyzer.analyze(js)
        assert "https://api.github.com/orgs/nodejs" in urls(eps)

    def test_fetch_with_custom_headers(self, analyzer: JSASTAnalyzer):
        """Source: justsml/fetch-api-examples - custom User-Agent"""
        js = """
        fetch('https://api.github.com/orgs/nodejs', {
            headers: {
                'User-agent': 'Mozilla/4.0 Custom User Agent'
            }
        })
        .then(response => response.json());
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "https://api.github.com/orgs/nodejs"]
        assert len(found) >= 1
        # Header param extracted
        header_params = [p for p in found[0].parameters if p.location.value == "header"]
        assert any(p.name == "User-agent" for p in header_params)

    def test_fetch_post_with_method_and_headers_object(self, analyzer: JSASTAnalyzer):
        """Source: justsml/fetch-api-examples - POST with headers and body"""
        js = """
        function postRequest(url, data) {
          return fetch(url, {
            credentials: 'same-origin',
            method: 'POST',
            body: JSON.stringify(data),
            headers: {
              'Content-Type': 'application/json'
            },
          });
        }
        """
        # url is a variable here - should NOT extract (dynamic)
        eps = analyzer.analyze(js)
        # This is expected: url is a function param, not a resolvable string
        # The analyzer should NOT crash, may or may not extract

    def test_fetch_with_template_literal_url(self, analyzer: JSASTAnalyzer):
        """Source: ivermac/fetch-basic-auth"""
        js = """
        let username = 'john';
        let password = 'doe';
        fetch(`https://httpbin.org/basic-auth/${username}/${password}`, {
            method: 'GET',
            headers: { 'Authorization': 'Basic dGVzdDp0ZXN0' }
        });
        """
        eps = analyzer.analyze(js)
        # Template literal with interpolation - should extract with {param} placeholders
        found = [e for e in eps if "httpbin.org" in e.url]
        assert len(found) >= 1

    def test_fetch_graphql_mutation(self, analyzer: JSASTAnalyzer):
        """Source: yusinto/graphql-mutation-fetch"""
        js = """
        const graphCoolEndpoint = 'https://api.graph.cool/simple/v1/abc123';

        const response = await fetch(graphCoolEndpoint, {
            headers: {'content-type': 'application/json'},
            method: 'POST',
            body: JSON.stringify({
                query: 'mutation { updateCountry(id: "1") { id } }'
            }),
        });
        """
        eps = analyzer.analyze(js)
        # Should resolve graphCoolEndpoint via base URL constants
        found = [e for e in eps if "graph.cool" in e.url]
        assert len(found) >= 1
        assert found[0].method == "POST"

    def test_fetch_relative_api_path(self, analyzer: JSASTAnalyzer):
        """Common pattern: fetch with relative path"""
        js = """
        fetch('/api/v1/users')
            .then(r => r.json())
            .then(data => setUsers(data));

        fetch('/api/v1/products', { method: 'GET' });
        """
        eps = analyzer.analyze(js)
        assert "/api/v1/users" in urls(eps)
        assert "/api/v1/products" in urls(eps)


# ======================================================================
# 2. axios
# ======================================================================


class TestAxios:
    """Real-world axios patterns from GitHub repos and gists."""

    def test_axios_get(self, analyzer: JSASTAnalyzer):
        """Source: moreta/axios-interceptor"""
        js = """
        import axios from 'axios';
        axios.get('/api/users').then(res => console.log(res.data));
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/users"]
        assert len(found) >= 1
        assert found[0].method == "GET"

    def test_axios_post_with_data(self, analyzer: JSASTAnalyzer):
        """Source: moreta/axios-interceptor"""
        js = """
        axios.post('/api/users', {
            name: 'John',
            email: 'john@example.com',
            role: 'admin'
        });
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/users"]
        assert len(found) >= 1
        assert found[0].method == "POST"
        param_names = [p.name for p in found[0].parameters]
        assert "name" in param_names
        assert "email" in param_names
        assert "role" in param_names

    def test_axios_put_delete_patch(self, analyzer: JSASTAnalyzer):
        """Multiple axios methods"""
        js = """
        axios.put('/api/users/1', { name: 'Updated' });
        axios.delete('/api/users/1');
        axios.patch('/api/users/1', { status: 'active' });
        """
        eps = analyzer.analyze(js)
        m = methods(eps)
        assert m.get("/api/users/1") in ("PUT", "DELETE", "PATCH")
        # At least one should be found (dedup by URL, first wins)
        assert "/api/users/1" in urls(eps)

    def test_axios_instance_crud(self, analyzer: JSASTAnalyzer):
        """Source: moreta/axios-interceptor - http instance methods"""
        js = """
        import { http } from './http';

        export default {
          find(query) {
            return http.get('/test', { params: query });
          },
          create(params) {
            return http.post('/test', { test: params });
          },
          update(params) {
            return http.put('/test', { test: params });
          }
        }
        """
        eps = analyzer.analyze(js)
        # 'http' is in the recognized object names
        found = [e for e in eps if e.url == "/test"]
        assert len(found) >= 1

    def test_axios_with_template_literal(self, analyzer: JSASTAnalyzer):
        """axios with template literal URL"""
        js = """
        const userId = 42;
        axios.get(`/api/users/${userId}/profile`);
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "users" in e.url and "profile" in e.url]
        assert len(found) >= 1

    def test_axios_post_auth_refresh(self, analyzer: JSASTAnalyzer):
        """Source: Godofbrowser/axios-refresh-multiple-request"""
        js = """
        axios.post('http://localhost:8000/auth/refresh', { refreshToken })
            .then(({data}) => {
                window.localStorage.setItem('token', data.token);
            });
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "auth/refresh" in e.url]
        assert len(found) >= 1
        assert found[0].method == "POST"

    def test_api_client_methods(self, analyzer: JSASTAnalyzer):
        """Common pattern: custom api/client instance"""
        js = """
        const api = axios.create({ baseURL: '/api/v2' });
        api.get('/users');
        api.post('/orders', { item: 'widget', qty: 5 });
        client.delete('/sessions/current');
        """
        eps = analyzer.analyze(js)
        # 'api' and 'client' are recognized object names
        assert any("users" in e.url for e in eps)
        assert any("orders" in e.url for e in eps)
        assert any("sessions" in e.url for e in eps)


# ======================================================================
# 3. jQuery AJAX
# ======================================================================


class TestJQuery:
    """Real-world jQuery AJAX patterns from devtut.github.io/jquery."""

    def test_jquery_ajax_post(self, analyzer: JSASTAnalyzer):
        """Source: devtut jQuery Ajax"""
        js = """
        $.ajax({
            type: 'POST',
            url: '/api/endpoint',
            data: { someData: true, name: 'test' }
        });
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/endpoint"]
        assert len(found) >= 1
        assert found[0].method == "POST"
        param_names = [p.name for p in found[0].parameters]
        assert "someData" in param_names
        assert "name" in param_names

    def test_jquery_ajax_with_method_key(self, analyzer: JSASTAnalyzer):
        """$.ajax with 'method' instead of 'type'"""
        js = """
        $.ajax({
            method: "POST",
            url: "/json-consuming-route",
            contentType: "application/json",
            data: JSON.stringify({
                author: {
                    name: "Bullwinkle J. Moose",
                    email: "bullwinkle@example.com"
                }
            })
        });
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/json-consuming-route"]
        assert len(found) >= 1
        assert found[0].method == "POST"

    def test_jquery_get_shorthand(self, analyzer: JSASTAnalyzer):
        """$.get() shorthand"""
        js = """
        $.get('/api/v1/status', function(data) {
            console.log(data);
        });
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/v1/status"]
        assert len(found) >= 1
        assert found[0].method == "GET"

    def test_jquery_post_shorthand(self, analyzer: JSASTAnalyzer):
        """Source: devtut jQuery Ajax"""
        js = """
        $.post('/api/submit',
            { date1Name: 'data1Value', date2Name: 'data2Value' },
            function(data) {
                console.log(data);
            }
        );
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/submit"]
        assert len(found) >= 1
        assert found[0].method == "POST"
        param_names = [p.name for p in found[0].parameters]
        assert "date1Name" in param_names

    def test_jquery_getjson(self, analyzer: JSASTAnalyzer):
        """$.getJSON shorthand"""
        js = """
        $.getJSON('/api/data', function(data) {
            console.log(data);
        });
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/data"]
        assert len(found) >= 1
        assert found[0].method == "GET"

    def test_jquery_ajax_form_upload(self, analyzer: JSASTAnalyzer):
        """Source: devtut jQuery Ajax - file upload with FormData"""
        js = """
        $.ajax({
            url: "/api/upload",
            type: "post",
            data: fdata,
            processData: false,
            contentType: false
        });
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/upload"]
        assert len(found) >= 1
        assert found[0].method == "POST"

    def test_jquery_ajax_with_statuscode(self, analyzer: JSASTAnalyzer):
        """$.ajax with statusCode callbacks"""
        js = """
        $.ajax({
            type: 'POST',
            url:  '/api/endpoint',
            data: {someData: true},
            statusCode: {
                404: function(responseObject) {},
                503: function(responseObject) {}
            }
        })
        .done(function(data){ alert(data); });
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/endpoint"]
        assert len(found) >= 1
        assert found[0].method == "POST"


# ======================================================================
# 4. XMLHttpRequest
# ======================================================================


class TestXHR:
    """Real-world XMLHttpRequest patterns from EtienneR/xhr-restful."""

    def test_xhr_get(self, analyzer: JSASTAnalyzer):
        """Source: EtienneR/xhr-restful"""
        js = """
        var url = "http://localhost:8080/api/v1/users";
        var xhr = new XMLHttpRequest();
        xhr.open('GET', url, true);
        xhr.send(null);
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "localhost:8080" in e.url]
        assert len(found) >= 1
        assert found[0].method == "GET"

    def test_xhr_post(self, analyzer: JSASTAnalyzer):
        """Source: EtienneR/xhr-restful"""
        js = """
        var url = "http://localhost:8080/api/v1/users";
        var xhr = new XMLHttpRequest();
        xhr.open("POST", url, true);
        xhr.setRequestHeader('Content-type','application/json');
        xhr.send(JSON.stringify({firstname: "John", lastname: "Snow"}));
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "localhost:8080" in e.url]
        assert len(found) >= 1
        assert found[0].method == "POST"

    def test_xhr_put(self, analyzer: JSASTAnalyzer):
        """Source: EtienneR/xhr-restful"""
        js = """
        var xhr = new XMLHttpRequest();
        xhr.open("PUT", "http://localhost:8080/api/v1/users/12", true);
        xhr.send(null);
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "users/12" in e.url]
        assert len(found) >= 1
        assert found[0].method == "PUT"

    def test_xhr_delete(self, analyzer: JSASTAnalyzer):
        """Source: EtienneR/xhr-restful"""
        js = """
        var xhr = new XMLHttpRequest();
        xhr.open("DELETE", "http://localhost:8080/api/v1/users/12", true);
        xhr.send(null);
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "users/12" in e.url]
        assert len(found) >= 1
        assert found[0].method == "DELETE"

    def test_xhr_form_urlencoded_post(self, analyzer: JSASTAnalyzer):
        """Source: bartmika/xhr-django"""
        js = """
        var xhttp = new XMLHttpRequest();
        xhttp.open('POST', '/api/add', true);
        xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xhttp.send("a=1&b=2");
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/add"]
        assert len(found) >= 1
        assert found[0].method == "POST"

    def test_xhr_url_variable_resolution(self, analyzer: JSASTAnalyzer):
        """XHR with URL in a variable - tests base URL resolution"""
        js = """
        const apiUrl = "https://api.example.com/v1";
        var xhr = new XMLHttpRequest();
        xhr.open("GET", apiUrl, true);
        xhr.send();
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "api.example.com" in e.url]
        assert len(found) >= 1


# ======================================================================
# 5. React Router
# ======================================================================


class TestReactRouter:
    """Real-world React Router patterns from GitHub repos."""

    def test_react_router_v6_basic_routes(self, analyzer: JSASTAnalyzer):
        """Source: arinthros/react-router-v6-nesting"""
        jsx = """
        import { Route, Routes } from 'react-router-dom';

        function AppRoutes() {
          return (
            <Routes>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/profile" element={<Profile />} />
            </Routes>
          );
        }
        """
        eps = analyzer.analyze(jsx)
        found_urls = urls(eps)
        assert "/dashboard" in found_urls
        assert "/settings" in found_urls
        assert "/profile" in found_urls

    def test_react_router_nested_routes(self, analyzer: JSASTAnalyzer):
        """Source: arinthros/react-router-v6-nesting - nested routes"""
        jsx = """
        <Routes>
          <Route path="/settings" element={<Settings />}>
            <Route path="/settings/people" element={<PeopleSettings />} />
            <Route path="/settings/security" element={<SecuritySettings />} />
          </Route>
        </Routes>
        """
        eps = analyzer.analyze(jsx)
        found_urls = urls(eps)
        assert "/settings" in found_urls
        assert "/settings/people" in found_urls
        assert "/settings/security" in found_urls

    def test_react_router_dynamic_params(self, analyzer: JSASTAnalyzer):
        """Source: dnshko/React-Router-V6 - dynamic params (wrapped in Routes)"""
        jsx = """
        <Routes>
          <Route path="/products/:id" element={<ProductPage />} />
          <Route path="/users/:userId/posts" element={<UserPosts />} />
        </Routes>
        """
        eps = analyzer.analyze(jsx)
        found_urls = urls(eps)
        assert "/products/:id" in found_urls
        assert "/users/:userId/posts" in found_urls

    def test_react_router_self_closing(self, analyzer: JSASTAnalyzer):
        """Self-closing Route components (wrapped in Routes)"""
        jsx = """
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
        </Routes>
        """
        eps = analyzer.analyze(jsx)
        found_urls = urls(eps)
        assert "/login" in found_urls
        assert "/register" in found_urls
        assert "/forgot-password" in found_urls


# ======================================================================
# 6. Vue Router
# ======================================================================


class TestVueRouter:
    """Real-world Vue Router patterns from vue-router docs and repos."""

    def test_vue_router_basic(self, analyzer: JSASTAnalyzer):
        """Source: louis70109/vue3-router"""
        js = """
        import { createRouter, createWebHistory } from "vue-router";

        const router = createRouter({
          history: createWebHistory(),
          routes: [
            { path: "/", component: Home },
            { path: "/about", component: About },
            { path: "/contact", component: Contact },
          ],
        });
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/" in found_urls
        assert "/about" in found_urls
        assert "/contact" in found_urls

    def test_vue_router_nested_children(self, analyzer: JSASTAnalyzer):
        """Source: vuejs/vue-router - nested routes"""
        js = """
        const router = new VueRouter({
          routes: [
            {
              path: '/clients',
              component: Clients,
              children: [
                {
                  path: '/clients/:id',
                  component: Client,
                  children: [
                    { path: '/clients/:id/visits', component: ClientVisits }
                  ]
                }
              ]
            }
          ]
        });
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/clients" in found_urls
        assert "/clients/:id" in found_urls
        assert "/clients/:id/visits" in found_urls

    def test_vue_router_multiple_routes(self, analyzer: JSASTAnalyzer):
        """Source: vuejs/vue-router issue discussions"""
        js = """
        const routes = [
          {
            path: '/',
            component: HomeMainContent,
            children: [
              { path: '/in-theaters', component: MovieList },
              { path: '/coming-soon', component: ComingSoonList },
              { path: '/trailers', component: TrailerList },
            ]
          },
          { path: '/about', component: About },
        ];
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/" in found_urls
        assert "/in-theaters" in found_urls
        assert "/coming-soon" in found_urls
        assert "/about" in found_urls


# ======================================================================
# 7. Angular Router
# ======================================================================


class TestAngularRouter:
    """Angular route definitions - detected via path: '...' pairs."""

    def test_angular_basic_routes(self, analyzer: JSASTAnalyzer):
        """Source: wesleygrimes/angular-routing-best-practices"""
        # Note: Angular uses TypeScript, but the path: '...' pattern is valid JS too
        js = """
        const AppRoutes = [
          { path: '/', pathMatch: 'full', redirectTo: 'feature-one' },
          { path: '/feature-one', loadChildren: './feature-one.module' },
          { path: '/feature-two', loadChildren: './feature-two.module' },
        ];
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/" in found_urls
        assert "/feature-one" in found_urls
        assert "/feature-two" in found_urls


# ======================================================================
# 8. Secret Detection
# ======================================================================


class TestSecrets:
    """Secret detection from real-world patterns."""

    def test_aws_access_key(self, analyzer: JSASTAnalyzer):
        """Source: trufflesecurity/trufflehog patterns"""
        js = """
        const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
        """
        secrets = analyzer.extract_secrets(js)
        assert any(s.kind == "aws_access_key" for s in secrets)
        assert any("AKIAIOSFODNN7EXAMPLE" in s.value for s in secrets)

    def test_jwt_token(self, analyzer: JSASTAnalyzer):
        """JWT token detection"""
        js = """
        const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        """
        secrets = analyzer.extract_secrets(js)
        assert any(s.kind == "jwt_token" for s in secrets)

    def test_api_key_variable(self, analyzer: JSASTAnalyzer):
        """Source: derzorngottes/hide-api-keys"""
        js = """
        const api_key = "sk_test_fake1234567890ab";
        """
        secrets = analyzer.extract_secrets(js)
        assert any(s.kind == "credential" for s in secrets)
        assert any("sk_test_fake1234567890ab" in s.value for s in secrets)

    def test_secret_key_variable(self, analyzer: JSASTAnalyzer):
        """Variable named secret_key"""
        js = """
        var secret_key = "super_secret_value_1234";
        """
        secrets = analyzer.extract_secrets(js)
        assert any(s.kind == "credential" for s in secrets)

    def test_access_token_variable(self, analyzer: JSASTAnalyzer):
        """Variable named access_token"""
        js = """
        let access_token = "xoxb-1234567890-abcdefghij";
        """
        secrets = analyzer.extract_secrets(js)
        assert any(s.kind == "credential" for s in secrets)

    def test_password_variable(self, analyzer: JSASTAnalyzer):
        """Variable named password"""
        js = """
        const password = "P@ssw0rd!2024";
        """
        secrets = analyzer.extract_secrets(js)
        assert any(s.kind == "credential" for s in secrets)

    def test_object_pair_secret(self, analyzer: JSASTAnalyzer):
        """Secret in object property (pair node)"""
        js = """
        var config = {
            api_key: '12345678abcdef90',
            secret_key: 'mysupersecretkey123'
        };
        """
        secrets = analyzer.extract_secrets(js)
        assert len(secrets) >= 2

    def test_short_values_ignored(self, analyzer: JSASTAnalyzer):
        """Values shorter than 8 chars should be ignored"""
        js = """
        const api_key = "short";
        """
        secrets = analyzer.extract_secrets(js)
        assert len(secrets) == 0

    def test_no_false_positives_regular_vars(self, analyzer: JSASTAnalyzer):
        """Regular variable names should not trigger secret detection"""
        js = """
        const username = "john_doe";
        const email = "john@example.com";
        const name = "some_name_value_here";
        """
        secrets = analyzer.extract_secrets(js)
        assert len(secrets) == 0


# ======================================================================
# 9. Base URL Constants (Pass 1)
# ======================================================================


class TestBaseURLConstants:
    """Test base URL extraction and resolution."""

    def test_base_url_with_fetch(self, analyzer: JSASTAnalyzer):
        """Base URL constant used in fetch call"""
        js = """
        const API_BASE = "https://api.example.com";
        fetch(API_BASE + "/users");
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "api.example.com" in e.url and "users" in e.url]
        assert len(found) >= 1

    def test_base_url_with_axios(self, analyzer: JSASTAnalyzer):
        """Base URL constant used in axios"""
        js = """
        const apiEndpoint = "https://backend.myapp.com/api/v1";
        axios.get(apiEndpoint + "/orders");
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "backend.myapp.com" in e.url and "orders" in e.url]
        assert len(found) >= 1

    def test_relative_base_url(self, analyzer: JSASTAnalyzer):
        """Relative base URL constant"""
        js = """
        const baseUrl = "/api/v2";
        fetch(baseUrl + "/products");
        """
        eps = analyzer.analyze(js)
        found = [e for e in eps if "/api/v2/products" in e.url]
        assert len(found) >= 1


# ======================================================================
# 10. String Literal URLs (Pass 3 - fallback)
# ======================================================================


class TestStringLiteralURLs:
    """Test the lower-confidence string literal URL extraction."""

    def test_api_path_strings(self, analyzer: JSASTAnalyzer):
        """API paths in string literals"""
        js = """
        const routes = {
            users: "/api/v1/users",
            products: "/api/v2/products",
            graphql: "/graphql"
        };
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/api/v1/users" in found_urls
        assert "/api/v2/products" in found_urls
        assert "/graphql" in found_urls

    def test_auth_paths(self, analyzer: JSASTAnalyzer):
        """Auth-related paths"""
        js = """
        const loginUrl = "/auth/login";
        const logoutUrl = "/auth/logout";
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/auth/login" in found_urls
        assert "/auth/logout" in found_urls

    def test_admin_and_internal_paths(self, analyzer: JSASTAnalyzer):
        """Admin and internal paths"""
        js = """
        const paths = [
            "/admin/dashboard",
            "/internal/health",
        ];
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/admin/dashboard" in found_urls
        assert "/internal/health" in found_urls

    def test_full_url_strings(self, analyzer: JSASTAnalyzer):
        """Full HTTP URLs in strings"""
        js = """
        const endpoints = [
            "https://api.stripe.com/v1/charges",
            "https://hooks.slack.com/services/T00000/B00000/XXXX",
        ];
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "https://api.stripe.com/v1/charges" in found_urls
        assert "https://hooks.slack.com/services/T00000/B00000/XXXX" in found_urls

    def test_websocket_paths(self, analyzer: JSASTAnalyzer):
        """WebSocket paths"""
        js = """
        const wsUrl = "/ws/notifications";
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/ws/notifications" in found_urls


# ======================================================================
# 11. Edge Cases & Complex Patterns
# ======================================================================


class TestEdgeCases:
    """Edge cases and complex patterns found in real-world code."""

    def test_url_concatenation_with_plus(self, analyzer: JSASTAnalyzer):
        """Source: EtienneR/xhr-restful - URL concatenation"""
        js = """
        var url = "http://localhost:8080/api/v1/users";
        var xhr = new XMLHttpRequest();
        xhr.open('PUT', url + '/12', true);
        """
        eps = analyzer.analyze(js)
        # Should resolve url variable or at minimum find the base URL
        assert len(eps) >= 1

    def test_multiple_fetch_calls_dedup(self, analyzer: JSASTAnalyzer):
        """Same URL from different call sites should be deduped"""
        js = """
        fetch('/api/v1/users');
        fetch('/api/v1/users');
        fetch('/api/v1/users');
        """
        eps = analyzer.analyze(js)
        user_eps = [e for e in eps if e.url == "/api/v1/users"]
        assert len(user_eps) == 1  # Dedup should collapse these

    def test_empty_source(self, analyzer: JSASTAnalyzer):
        """Empty source should not crash"""
        eps = analyzer.analyze("")
        assert eps == []
        secrets = analyzer.extract_secrets("")
        assert secrets == []

    def test_malformed_javascript(self, analyzer: JSASTAnalyzer):
        """Malformed JS should not crash the analyzer"""
        js = """
        function( { broken syntax here
        fetch('/api/v1/data'
        const = ;
        """
        # Should not raise, may or may not extract partial results
        eps = analyzer.analyze(js)
        # tree-sitter is tolerant of errors, may still find the fetch
        assert isinstance(eps, list)

    def test_minified_javascript(self, analyzer: JSASTAnalyzer):
        """Minified JS (no whitespace)"""
        js = 'fetch("/api/users");axios.post("/api/orders",{item:"a",qty:1});'
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/api/users" in found_urls
        assert "/api/orders" in found_urls

    def test_bytes_input(self, analyzer: JSASTAnalyzer):
        """Bytes input should work same as string"""
        js_bytes = b'fetch("/api/v1/test");'
        eps = analyzer.analyze(js_bytes)
        assert "/api/v1/test" in urls(eps)

    def test_utf8_in_source(self, analyzer: JSASTAnalyzer):
        """UTF-8 characters in source should not crash"""
        js = """
        // Comment with unicode: 한국어 日本語 中文
        fetch('/api/v1/search?q=テスト');
        """
        eps = analyzer.analyze(js)
        assert isinstance(eps, list)

    def test_source_url_propagation(self, analyzer: JSASTAnalyzer):
        """source_file should be set on extracted endpoints"""
        js = 'fetch("/api/v1/data");'
        eps = analyzer.analyze(js, source_url="https://example.com/app.js")
        assert len(eps) >= 1
        assert eps[0].source_file == "https://example.com/app.js"

    def test_line_number_tracking(self, analyzer: JSASTAnalyzer):
        """Line numbers should be tracked"""
        js = """line1
line2
line3
fetch('/api/v1/test');
"""
        eps = analyzer.analyze(js)
        found = [e for e in eps if e.url == "/api/v1/test"]
        assert len(found) >= 1
        assert found[0].line_number == 4  # 1-indexed

    def test_confidence_levels(self, analyzer: JSASTAnalyzer):
        """Pass 2 (call sites) should have higher confidence than Pass 3 (strings)"""
        js = """
        fetch('/api/v1/explicit');
        const fallback = "/api/v2/fallback-only-in-string";
        """
        eps = analyzer.analyze(js)
        explicit = [e for e in eps if e.url == "/api/v1/explicit"]
        # If fallback was extracted via string literal, it should have lower confidence
        fallback = [e for e in eps if "fallback" in e.url]
        if explicit:
            assert explicit[0].confidence == 1.0
        if fallback:
            assert fallback[0].confidence == 0.6

    def test_request_object_methods(self, analyzer: JSASTAnalyzer):
        """'request' as object name for HTTP calls"""
        js = """
        request.get('/api/health');
        request.post('/api/data', { key: 'value' });
        """
        eps = analyzer.analyze(js)
        assert any("health" in e.url for e in eps)
        assert any("data" in e.url for e in eps)

    def test_tags_identify_source(self, analyzer: JSASTAnalyzer):
        """Tags should identify the extraction method"""
        js = """
        fetch('/api/from-fetch');
        axios.get('/api/from-axios');
        """
        eps = analyzer.analyze(js)
        fetch_ep = [e for e in eps if "from-fetch" in e.url]
        axios_ep = [e for e in eps if "from-axios" in e.url]
        if fetch_ep:
            assert "fetch" in fetch_ep[0].tags
        if axios_ep:
            assert "axios" in axios_ep[0].tags


# ======================================================================
# 12. Mixed Real-World File (Integration)
# ======================================================================


class TestIntegration:
    """Full realistic JS file with multiple patterns."""

    def test_realistic_app_js(self, analyzer: JSASTAnalyzer):
        """A realistic app.js combining multiple patterns"""
        js = """
        // Config
        const API_BASE = "https://api.myapp.com/v1";
        const api_key = "sk_test_FAKE_KEY_FOR_UNIT_TEST_00";

        // Fetch calls
        async function loadUsers() {
            const res = await fetch(API_BASE + "/users", {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            });
            return res.json();
        }

        async function createUser(userData) {
            return fetch('/api/v1/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
        }

        // Axios
        axios.get('/api/v1/products');
        axios.post('/api/v1/orders', { product_id: 1, quantity: 2 });

        // XHR
        var xhr = new XMLHttpRequest();
        xhr.open("DELETE", "/api/v1/sessions", true);
        xhr.send();

        // jQuery
        $.ajax({
            url: '/api/v1/search',
            type: 'GET',
            data: { q: 'test' }
        });

        // Routes
        const routes = [
            { path: '/dashboard', component: Dashboard },
            { path: '/settings', component: Settings },
            { path: '/admin/users', component: AdminUsers },
        ];
        """
        eps = analyzer.analyze(js)
        secrets = analyzer.extract_secrets(js)

        found_urls = urls(eps)

        # Endpoints from various sources
        assert any("users" in u for u in found_urls)
        assert "/api/v1/products" in found_urls
        assert any("orders" in u for u in found_urls)
        assert any("sessions" in u for u in found_urls)
        assert any("search" in u for u in found_urls)

        # Routes
        assert "/dashboard" in found_urls
        assert "/settings" in found_urls
        assert "/admin/users" in found_urls

        # Secrets
        assert any("sk_test_FAKE_KEY_FOR_UNIT_TEST_00" in s.value for s in secrets)

    def test_spa_with_react_router_and_api(self, analyzer: JSASTAnalyzer):
        """SPA with React Router and API calls"""
        jsx = """
        import React from 'react';
        import { Route, Routes } from 'react-router-dom';

        const App = () => (
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/users/:id" element={<UserProfile />} />
          </Routes>
        );

        // API Service
        const fetchUser = (id) => fetch(`/api/users/${id}`);
        const updateUser = (id, data) => fetch(`/api/users/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        axios.get('/api/notifications');
        """
        eps = analyzer.analyze(jsx)
        found_urls = urls(eps)

        # Routes
        assert "/" in found_urls
        assert "/login" in found_urls
        assert "/dashboard" in found_urls
        assert "/users/:id" in found_urls

        # API calls
        assert "/api/notifications" in found_urls


# ======================================================================
# 13. Inline Script Extraction
# ======================================================================


class TestInlineScriptExtraction:
    """Test the _extract_inline_scripts static method."""

    def test_single_script(self):
        """Extract single inline script"""
        from prowl.modules.s4_js_analysis import JSAnalysisModule
        html = b"""
        <html>
        <head><title>Test</title></head>
        <body>
        <script>
        fetch('/api/v1/data');
        var secret_key = "mysecretkeythatislong";
        </script>
        </body>
        </html>
        """
        scripts = JSAnalysisModule._extract_inline_scripts(html)
        assert len(scripts) == 1
        assert "fetch" in scripts[0]

    def test_multiple_scripts(self):
        """Extract multiple inline scripts"""
        from prowl.modules.s4_js_analysis import JSAnalysisModule
        html = b"""
        <html>
        <script>var a = 1; fetch('/api/first/endpoint/here');</script>
        <script type="text/javascript">
        axios.get('/api/second/endpoint/here');
        </script>
        <script>
        // Third script
        $.ajax({ url: '/api/third/endpoint/here', method: 'POST' });
        </script>
        </html>
        """
        scripts = JSAnalysisModule._extract_inline_scripts(html)
        assert len(scripts) == 3

    def test_short_scripts_exist(self):
        """Very short scripts are still extracted (filtering happens in run())"""
        from prowl.modules.s4_js_analysis import JSAnalysisModule
        html = b"""
        <script>var x=1;</script>
        <script>fetch('/api/v1/real-endpoint-with-sufficient-length');</script>
        """
        scripts = JSAnalysisModule._extract_inline_scripts(html)
        assert len(scripts) == 2  # Both extracted, length filter is in run()

    def test_script_with_attributes(self):
        """Scripts with src/type attributes"""
        from prowl.modules.s4_js_analysis import JSAnalysisModule
        html = b"""
        <script src="app.js"></script>
        <script type="module">
        import { api } from './api.js';
        fetch('/api/v1/module-endpoint');
        </script>
        """
        scripts = JSAnalysisModule._extract_inline_scripts(html)
        # src-only script has no content between tags
        # module script has content
        assert any("/api/v1/module-endpoint" in s for s in scripts)


# ======================================================================
# 14. Obfuscation Resilience
# ======================================================================


class TestObfuscation:
    """Test handling of obfuscated JavaScript patterns."""

    # --- Hex / Unicode escape decoding ---

    def test_hex_encoded_url(self, analyzer: JSASTAnalyzer):
        r"""Hex escape: \x2f\x61\x70\x69 = /api"""
        js = r"""
        var _0x1a2b = '\x2f\x61\x70\x69\x2f\x76\x31\x2f\x75\x73\x65\x72\x73';
        fetch(_0x1a2b);
        """
        eps = analyzer.analyze(js)
        assert any("/api/v1/users" in e.url for e in eps)

    def test_unicode_encoded_url(self, analyzer: JSASTAnalyzer):
        r"""Unicode escape: \u002f\u0061\u0070\u0069 = /api"""
        js = r"""
        var apiUrl = '\u002f\u0061\u0070\u0069\u002f\u0076\u0031\u002f\u0064\u0061\u0074\u0061';
        fetch(apiUrl);
        """
        eps = analyzer.analyze(js)
        assert any("/api/v1/data" in e.url for e in eps)

    def test_hex_in_fetch_direct(self, analyzer: JSASTAnalyzer):
        r"""Hex escape directly in fetch argument"""
        js = r"""fetch('\x2f\x61\x70\x69\x2f\x68\x65\x61\x6c\x74\x68');"""
        eps = analyzer.analyze(js)
        assert any("/api/health" in e.url for e in eps)

    def test_mixed_escape_and_plain(self, analyzer: JSASTAnalyzer):
        r"""Mix of hex escapes and plain text"""
        js = r"""
        fetch('/api\x2f\x76\x31/users');
        """
        eps = analyzer.analyze(js)
        assert any("/api/v1/users" in e.url for e in eps)

    # --- Variable mangling (webpack/terser) ---

    def test_webpack_mangled_vars(self, analyzer: JSASTAnalyzer):
        """Webpack/terser style: strings intact, vars mangled"""
        js = """var n="/api/v1/users",o="POST";fetch(n,{method:o,headers:{"Content-Type":"application/json"},body:JSON.stringify({name:"test"})});"""
        eps = analyzer.analyze(js)
        assert "/api/v1/users" in urls(eps)

    def test_webpack_chunk_module(self, analyzer: JSASTAnalyzer):
        """Webpack module chunk with fetch calls"""
        js = """
        (self.webpackChunk=self.webpackChunk||[]).push([[179],{
          52379:function(e,t,r){
            e.exports={
              fetchUsers:function(){return fetch("/api/v1/users")},
              createOrder:function(e){return fetch("/api/v1/orders",{method:"POST",body:JSON.stringify(e)})},
              deleteItem:function(e){return fetch("/api/v1/items/"+e,{method:"DELETE"})}
            }
          }
        }]);
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/api/v1/users" in found_urls
        assert "/api/v1/orders" in found_urls

    # --- Array-based string storage ---

    def test_array_string_storage(self, analyzer: JSASTAnalyzer):
        """URLs stored in array (Pass 3 string literal catches them)"""
        js = """
        var _0xabc = ['/api/v1/users', 'POST', '/api/v1/orders', 'GET'];
        fetch(_0xabc[0], { method: _0xabc[1] });
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/api/v1/users" in found_urls
        assert "/api/v1/orders" in found_urls

    # --- Proxy/lookup function ---

    def test_proxy_function_strings_caught(self, analyzer: JSASTAnalyzer):
        """javascript-obfuscator proxy function: strings in array still caught"""
        js = """
        function _0x4a2c(_0x1b) {
            var _0x3d = ['/api/v1/login', '/api/v1/register', '/api/v1/profile'];
            return _0x3d[_0x1b];
        }
        var _0xurl1 = _0x4a2c(0);
        fetch(_0xurl1, { method: 'POST' });
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "/api/v1/login" in found_urls
        assert "/api/v1/register" in found_urls
        assert "/api/v1/profile" in found_urls

    # --- Bracket notation ---

    def test_bracket_notation_calls(self, analyzer: JSASTAnalyzer):
        """Bracket notation method calls: window['fetch']"""
        js = """
        window['fetch']('/api/v1/test');
        """
        eps = analyzer.analyze(js)
        assert "/api/v1/test" in urls(eps)

    # --- Bracket notation secrets ---

    def test_bracket_notation_secret(self, analyzer: JSASTAnalyzer):
        """config['api_key'] = '...' should detect secret"""
        js = """
        var config = {};
        config['api_key'] = 'my_super_secret_api_key_value';
        """
        secrets = analyzer.extract_secrets(js)
        assert any(s.kind == "credential" for s in secrets)
        assert any("my_super_secret_api_key_value" in s.value for s in secrets)

    def test_bracket_notation_token(self, analyzer: JSASTAnalyzer):
        """obj['access_token'] = '...' should detect secret"""
        js = """
        var session = {};
        session['access_token'] = 'xoxb-1234567890-abcdefghij';
        """
        secrets = analyzer.extract_secrets(js)
        assert any(s.kind == "credential" for s in secrets)

    # --- Ternary / conditional URLs ---

    def test_ternary_url_both_branches(self, analyzer: JSASTAnalyzer):
        """Both branches of ternary caught (as string literals)"""
        js = """
        var isProd = true;
        var apiUrl = isProd ? 'https://api.prod.com/v1' : 'https://api.dev.com/v1';
        fetch(apiUrl + '/users');
        """
        eps = analyzer.analyze(js)
        found_urls = urls(eps)
        assert "https://api.prod.com/v1" in found_urls
        assert "https://api.dev.com/v1" in found_urls

    # --- Known limitations (should not crash) ---

    def test_fromcharcode_no_crash(self, analyzer: JSASTAnalyzer):
        """String.fromCharCode - can't resolve but should not crash"""
        js = """
        var url = String.fromCharCode(47,97,112,105);
        fetch(url);
        """
        eps = analyzer.analyze(js)
        # May or may not find the URL, but must not crash
        assert isinstance(eps, list)

    def test_atob_no_crash(self, analyzer: JSASTAnalyzer):
        """atob() - can't resolve but should not crash"""
        js = """
        var url = atob('L2FwaS92MS91c2Vycw==');
        fetch(url);
        """
        eps = analyzer.analyze(js)
        assert isinstance(eps, list)

    def test_eval_no_crash(self, analyzer: JSASTAnalyzer):
        """eval() - can't resolve but should not crash"""
        js = """eval("fetch('/api/v1/hidden')");"""
        eps = analyzer.analyze(js)
        assert isinstance(eps, list)
