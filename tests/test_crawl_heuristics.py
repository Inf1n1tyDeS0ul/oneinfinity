
import os
import sys

sys.path.insert(0, os.getcwd())

from modules.pipeline import extract_js_endpoints_and_params, build_get_form_urls


def test_extract_js_endpoints_and_params():
    js = """
      fetch('/api/users?id=1');
      axios.get("/rest/items?q=");
      const gql = "https://example.com/graphql";
      client.post('/internal/admin/reset?token=');
    """
    endpoints, params = extract_js_endpoints_and_params(js)
    assert any("/api/users" in e for e in endpoints)
    assert any("/rest/items" in e for e in endpoints)
    assert any("graphql" in e for e in endpoints)
    assert "id" in params
    assert "q" in params
    assert "token" in params


def test_build_get_form_urls():
    base = "https://example.com/"
    html = """
      <html>
        <body>
          <form action="/search" method="GET">
            <input type="text" name="q" />
            <input type="text" name="page" />
          </form>
        </body>
      </html>
    """
    urls = build_get_form_urls(base, html)
    assert urls
    assert any(u.startswith("https://example.com/search?") and "q=1" in u and "page=1" in u for u in urls)


if __name__ == "__main__":
    test_extract_js_endpoints_and_params()
    test_build_get_form_urls()
    print("[ok] crawl heuristic tests passed")

