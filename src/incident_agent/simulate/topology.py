"""The two applications ITBench deploys: the OpenTelemetry demo (Astronomy Shop) and Istio Bookinfo.

Call edges follow the upstream architecture diagrams. ``critical`` means a failed call fails the
caller's request; non-critical failures are logged and the request still succeeds.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Component:
    name: str  # Deployment name
    namespace: str
    service: str | None  # Kubernetes Service name (None: no Service)
    port: int
    image: str
    language: str
    protocol: str = "grpc"  # grpc | http | redis | kafka | sql
    replicas: int = 1
    env: dict[str, str] = field(default_factory=dict)
    secrets: list[str] = field(default_factory=list)
    configmaps: list[str] = field(default_factory=list)
    memory_limit: str = "256Mi"
    cpu_request: str = "50m"
    strategy: str = "RollingUpdate"
    telemetry_name: str | None = None  # service.name in traces/logs (defaults to name)
    infra: bool = False  # observability stack; not on the request path

    @property
    def instrumented(self) -> bool:
        """Emits its own spans (databases, caches and the broker do not)."""
        return self.protocol in ("grpc", "http") or (self.protocol == "kafka" and self.name != "kafka")

    @property
    def otel_name(self) -> str:
        return self.telemetry_name or self.name

    @property
    def labels(self) -> dict[str, str]:
        base = self.name.removesuffix("-v1").removesuffix("-v2").removesuffix("-v3")
        lbl = {"app.kubernetes.io/name": self.name, "app.kubernetes.io/component": self.name}
        if self.namespace == "book-info":
            lbl = {"app": base, "version": self.name.rsplit("-", 1)[-1] if self.name[-3:-1] == "-v" else "v1"}
        return lbl


@dataclass
class Edge:
    caller: str  # component name
    callee: str  # component name
    operation: str
    critical: bool = True


@dataclass
class Flow:
    """A user request: a tree of calls starting at the entry component."""

    name: str
    route: str
    calls: list[tuple]  # nested: (callee, operation, critical, [children])
    weight: float = 1.0


@dataclass
class Application:
    name: str
    namespace: str
    components: list[Component]
    flows: list[Flow]
    entry: str  # component receiving user traffic
    metrics_by_destination: bool = False  # Istio metrics are labelled by destination service

    def component(self, name: str) -> Component:
        for c in self.components:
            if c.name == name:
                return c
        raise KeyError(name)

    def by_service(self, service: str) -> list[Component]:
        return [c for c in self.components if c.service == service]

    def edges(self) -> list[Edge]:
        out: dict[tuple[str, str], Edge] = {}

        def walk(caller: str | None, calls: list[tuple]) -> None:
            for callee, op, critical, children in calls:
                if caller:
                    out.setdefault((caller, callee), Edge(caller, callee, op, critical))
                walk(callee, children)

        for f in self.flows:
            walk(None, f.calls)
        return list(out.values())


def _otel_demo() -> Application:
    ns = "otel-demo"

    def c(name, port, lang, protocol="grpc", **kw):
        return Component(name, ns, kw.pop("service", name), port, f"ghcr.io/open-telemetry/demo:2.1.3-{name}", lang,
                         protocol, **kw)

    addr = {f"{n.upper().replace('-', '_')}_ADDR": f"{n}:{p}" for n, p in [
        ("ad", 8080), ("cart", 8080), ("checkout", 8080), ("currency", 8080), ("email", 8080), ("payment", 8080),
        ("product-catalog", 8080), ("recommendation", 8080), ("shipping", 8080), ("quote", 8080),
        ("flagd", 8013), ("valkey", 6379), ("kafka", 9092), ("frontend", 8080), ("image-provider", 8081)]}
    addr["VALKEY_ADDR"] = "valkey-cart:6379"
    addr["DB_CONNECTION_STRING"] = "Host=postgresql;Username=otelu;Password=otelp;Database=otel"

    def env(*keys):
        return {k: addr[k] for k in keys}

    comps = [
        c("frontend-proxy", 8080, "cpp", "http", env=env("FRONTEND_ADDR", "IMAGE_PROVIDER_ADDR", "FLAGD_ADDR")),
        c("frontend", 8080, "javascript", "http", replicas=1, memory_limit="250Mi",
          env=env("AD_ADDR", "CART_ADDR", "CHECKOUT_ADDR", "CURRENCY_ADDR", "PRODUCT_CATALOG_ADDR",
                  "RECOMMENDATION_ADDR", "SHIPPING_ADDR", "FLAGD_ADDR")),
        c("ad", 8080, "java", env=env("FLAGD_ADDR"), memory_limit="300Mi"),
        c("cart", 8080, "dotnet", env=env("VALKEY_ADDR", "FLAGD_ADDR"), memory_limit="160Mi"),
        c("checkout", 8080, "go", env=env("CART_ADDR", "CURRENCY_ADDR", "EMAIL_ADDR", "PAYMENT_ADDR",
                                         "PRODUCT_CATALOG_ADDR", "SHIPPING_ADDR", "KAFKA_ADDR", "FLAGD_ADDR")),
        c("currency", 8080, "cpp"),
        c("email", 8080, "ruby", "http", secrets=["email-service-secret"], memory_limit="100Mi"),
        c("payment", 8080, "javascript", env=env("FLAGD_ADDR"), memory_limit="120Mi"),
        c("product-catalog", 8080, "go", env=env("FLAGD_ADDR")),
        c("recommendation", 8080, "python", env=env("PRODUCT_CATALOG_ADDR", "FLAGD_ADDR"), memory_limit="500Mi"),
        c("shipping", 8080, "rust", "http", env=env("QUOTE_ADDR")),
        c("quote", 8080, "php", "http"),
        c("accounting", 8080, "dotnet", "kafka", service=None, env=env("KAFKA_ADDR", "DB_CONNECTION_STRING")),
        c("fraud-detection", 8080, "kotlin", "kafka", service=None, env=env("KAFKA_ADDR", "FLAGD_ADDR")),
        c("kafka", 9092, "java", "kafka", memory_limit="600Mi", strategy="Recreate"),
        c("valkey-cart", 6379, "c", "redis", strategy="Recreate", memory_limit="20Mi",
          secrets=["valkey-credentials"]),
        c("postgresql", 5432, "c", "sql", strategy="Recreate"),
        c("flagd", 8013, "go", configmaps=["flagd-config"], memory_limit="75Mi"),
        c("image-provider", 8081, "c", "http"),
        c("load-generator", 8089, "python", "http", env={"LOCUST_HOST": "http://frontend-proxy:8080"}),
        c("otel-collector", 4317, "go", infra=True),
        c("jaeger", 16686, "go", "http", infra=True),
        c("prometheus", 9090, "go", "http", infra=True),
        c("grafana", 3000, "go", "http", infra=True, configmaps=["grafana-dashboards"]),
        c("opensearch", 9200, "java", "http", infra=True, memory_limit="1100Mi"),
    ]

    def call(callee, op, critical=True, *children):
        return (callee, op, critical, list(children))

    flag = call("flagd", "flagd.evaluation.v1.Service/ResolveBoolean", False)
    product = call("product-catalog", "oteldemo.ProductCatalogService/GetProduct", True, flag)
    proxy = "frontend-proxy"

    def via_proxy(*frontend_children, route):
        return [call(proxy, f"ingress {route}", True, call("frontend", f"GET {route}", True, *frontend_children))]

    flows = [
        Flow("browse", "/api/products", via_proxy(call("product-catalog", "oteldemo.ProductCatalogService/ListProducts",
                                                       True, flag),
                                                  call("currency", "oteldemo.CurrencyService/Convert"),
                                                  route="/api/products"), 3),
        Flow("product", "/api/products/{id}", via_proxy(product, call("currency", "oteldemo.CurrencyService/Convert"),
                                                        route="/api/products/{id}"), 3),
        Flow("recommend", "/api/recommendations",
             via_proxy(call("recommendation", "oteldemo.RecommendationService/ListRecommendations", True,
                            call("product-catalog", "oteldemo.ProductCatalogService/ListProducts"), flag),
                       route="/api/recommendations"), 2),
        Flow("ads", "/api/data", via_proxy(call("ad", "oteldemo.AdService/GetAds", True, flag), route="/api/data"), 2),
        Flow("cart", "/api/cart", via_proxy(call("cart", "oteldemo.CartService/AddItem", True,
                                                 call("valkey-cart", "HSET"), flag), route="/api/cart"), 2),
        Flow("shipping", "/api/shipping", via_proxy(call("shipping", "POST /get-quote", True,
                                                         call("quote", "POST /getquote")), route="/api/shipping"), 1),
        Flow("checkout", "/api/checkout", via_proxy(
            call("checkout", "oteldemo.CheckoutService/PlaceOrder", True,
                 call("cart", "oteldemo.CartService/GetCart", True, call("valkey-cart", "HGET")),
                 call("product-catalog", "oteldemo.ProductCatalogService/GetProduct"),
                 call("currency", "oteldemo.CurrencyService/Convert"),
                 call("shipping", "POST /get-quote", True, call("quote", "POST /getquote")),
                 call("payment", "oteldemo.PaymentService/Charge", True, flag),
                 call("email", "POST /send_order_confirmation", False),
                 call("kafka", "orders publish", False,
                      call("accounting", "orders process", False, call("postgresql", "INSERT order")),
                      call("fraud-detection", "orders process", False)),
                 call("cart", "oteldemo.CartService/EmptyCart", True, call("valkey-cart", "DEL"))),
            route="/api/checkout"), 1),
        Flow("images", "/images", [call(proxy, "ingress /images", True,
                                        call("image-provider", "GET /static/img"))], 1),
    ]
    return Application("opentelemetry-demo", ns, comps, flows, entry=proxy)


def _bookinfo() -> Application:
    ns = "book-info"

    def c(name, service, lang, **kw):
        return Component(name, ns, service, 9080, f"docker.io/istio/examples-bookinfo-{name}:1.20.3", lang, "http",
                         telemetry_name=f"{service}.{ns}", **kw)

    comps = [
        Component("bookinfo-gateway-istio", ns, "bookinfo-gateway-istio", 80, "docker.io/istio/proxyv2:1.27.1", "cpp",
                  "http", telemetry_name=f"bookinfo-gateway-istio.{ns}"),
        c("productpage-v1", "productpage", "python",
          env={"DETAILS_HOSTNAME": "details", "REVIEWS_HOSTNAME": "reviews"}),
        c("details-v1", "details", "ruby"),
        c("reviews-v1", "reviews", "java"),
        c("reviews-v2", "reviews", "java", env={"RATINGS_HOSTNAME": "ratings"}),
        c("reviews-v3", "reviews", "java", env={"RATINGS_HOSTNAME": "ratings"}),
        c("ratings-v1", "ratings", "javascript"),
    ]

    def call(callee, op, critical=True, *children):
        return (callee, op, critical, list(children))

    def page(reviews):
        ratings = [call("ratings-v1", "GET /ratings/0")] if reviews != "reviews-v1" else []
        return [call("bookinfo-gateway-istio", "ingress /productpage", True,
                     call("productpage-v1", "GET /productpage", True, call("details-v1", "GET /details/0", False),
                          call(reviews, "GET /reviews/0", False, *ratings)))]

    flows = [Flow(f"page-{r}", "/productpage", page(r), 1) for r in ("reviews-v1", "reviews-v2", "reviews-v3")]
    return Application("book-info", ns, comps, flows, entry="bookinfo-gateway-istio", metrics_by_destination=True)


APPLICATIONS = {"opentelemetry-demo": _otel_demo, "book-info": _bookinfo}


def application(app_id: str) -> Application:
    return APPLICATIONS[app_id]()
