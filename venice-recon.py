#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
venice-recon v3.0
Global government reconnaissance harness.

Subdomain enumeration, DNS/TLS intel, tech/WAF/auth fingerprinting, secret &
credential exposure scanning with soft-404 calibration, mass user enumeration
across 70+ endpoint families incl. LDAP/SMTP-VRFY/XML-RPC/Autodiscover/SAML
metadata/PGP keyservers, Gravatar confirmation, search-engine + Common Crawl
path mining, government email harvesting, JSON reporting.

Authorised testing only.
"""

import argparse
import base64
import concurrent.futures as cf
import csv
import hashlib
import io
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
import urllib.parse
import zipfile
from collections import defaultdict
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.reversename
    HAVE_DNS = True
except Exception:
    HAVE_DNS = False

try:
    import mmh3
    HAVE_MMH3 = True
except Exception:
    HAVE_MMH3 = False

VERSION = "3.0.0"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

class C:
    R = "\033[0m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[36m"
    M = "\033[35m"; RED = "\033[31m"; DIM = "\033[2m"

QUIET = False

def _tty():
    return sys.stdout.isatty()

def log(msg, level="INF"):
    if QUIET and level in ("DBG", "INF"):
        return
    col = {"INF": C.B, "OK": C.G, "WRN": C.Y, "ERR": C.RED, "DBG": C.DIM,
           "CRIT": C.M}.get(level, C.R)
    if _tty():
        print("%s[%s]%s %s" % (col, level, C.R, msg))
    else:
        print("[%s] %s" % (level, msg))

def banner():
    print(r"""
 __     __            _          ____
 \ \   / /__ _ __   (_) ___ ___|  _ \ ___  ___ ___  _ __
  \ \ / / _ \ '_ \  | |/ __/ _ \ |_) / _ \/ __/ _ \| '_ \
   \ V /  __/ | | | | | (_|  __/  _ <  __/ (_| (_) | | | |
    \_/ \___|_| |_| |_|\___\___|_| \_\___|\___\___/|_| |_|
""")
    print("  venice-recon v%s  |  global government recon\n" % VERSION)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def slug(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")

class RateLimiter:
    def __init__(self, rps):
        self.rps = max(0.1, float(rps))
        self.lock = threading.Lock()
        self.next_at = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            delay = self.next_at - now if now < self.next_at else 0.0
            self.next_at = max(now, self.next_at) + (1.0 / self.rps)
        if delay:
            time.sleep(delay + random.uniform(0, 0.02))

# ----------------------------------------------------------------------------
# government suffix table (ISO-3166 -> gov second level)
# ----------------------------------------------------------------------------

GOV_SLD = {
 "ad": "gov", "ae": "gov", "af": "gov", "ag": "gov", "al": "gov", "am": "gov",
 "ao": "gov", "ar": "gob", "at": "gv", "au": "gov", "az": "gov", "ba": "gov",
 "bb": "gov", "bd": "gov", "be": "gov", "bf": "gov", "bg": "government",
 "bh": "gov", "bi": "gov", "bj": "gouv", "bn": "gov", "bo": "gob", "br": "gov",
 "bs": "gov", "bt": "gov", "bw": "gov", "by": "gov", "bz": "gov", "ca": "gc",
 "cd": "gouv", "cf": "gouv", "cg": "gouv", "ch": "admin", "ci": "gouv",
 "cl": "gob", "cm": "gov", "cn": "gov", "co": "gov", "cr": "go", "cu": "gob",
 "cv": "gov", "cy": "gov", "cz": "gov", "de": "bund", "dj": "gouv", "dk": "gov",
 "dm": "gov", "do": "gob", "dz": "gov", "ec": "gob", "ee": "gov", "eg": "gov",
 "er": "gov", "es": "gob", "et": "gov", "fi": "gov", "fj": "gov", "fr": "gouv",
 "ga": "gouv", "gb": "gov", "gd": "gov", "ge": "gov", "gh": "gov", "gm": "gov",
 "gn": "gouv", "gq": "gob", "gr": "gov", "gt": "gob", "gw": "gov", "gy": "gov",
 "hn": "gob", "hr": "gov", "ht": "gouv", "hu": "gov", "id": "go", "ie": "gov",
 "il": "gov", "in": "gov", "iq": "gov", "ir": "gov", "is": "gov", "it": "gov",
 "jm": "gov", "jo": "gov", "jp": "go", "ke": "go", "kg": "gov", "kh": "gov",
 "ki": "gov", "km": "gouv", "kn": "gov", "kp": "gov", "kr": "go", "kw": "gov",
 "kz": "gov", "la": "gov", "lb": "gov", "lc": "gov", "li": "gov", "lk": "gov",
 "lr": "gov", "ls": "gov", "lt": "gov", "lu": "gov", "lv": "gov", "ly": "gov",
 "ma": "gov", "mc": "gouv", "md": "gov", "me": "gov", "mg": "gouv", "mh": "gov",
 "mk": "gov", "ml": "gouv", "mm": "gov", "mn": "gov", "mo": "gov", "mr": "gouv",
 "mt": "gov", "mu": "gov", "mv": "gov", "mw": "gov", "mx": "gob", "my": "gov",
 "mz": "gov", "na": "gov", "nc": "gouv", "ne": "gouv", "ng": "gov", "ni": "gob",
 "nl": "gov", "no": "gov", "np": "gov", "nr": "gov", "nz": "gov", "om": "gov",
 "pa": "gob", "pe": "gob", "pf": "gouv", "pg": "gov", "ph": "gov", "pk": "gov",
 "pl": "gov", "pt": "gov", "pw": "gov", "py": "gov", "qa": "gov", "ro": "gov",
 "rs": "gov", "ru": "gov", "rw": "gov", "sa": "gov", "sb": "gov", "sc": "gov",
 "sd": "gov", "se": "gov", "sg": "gov", "si": "gov", "sk": "gov", "sl": "gov",
 "sm": "gov", "sn": "gouv", "so": "gov", "sr": "gov", "ss": "gov", "st": "gov",
 "sv": "gob", "sy": "gov", "sz": "gov", "td": "gouv", "tg": "gouv", "th": "go",
 "tj": "gov", "tl": "gov", "tm": "gov", "tn": "gov", "to": "gov", "tr": "gov",
 "tt": "gov", "tv": "gov", "tw": "gov", "tz": "go", "ua": "gov", "ug": "go",
 "uk": "gov", "us": "gov", "uy": "gub", "uz": "gov", "va": "va", "vc": "gov",
 "ve": "gob", "vg": "gov", "vn": "gov", "vu": "gov", "ws": "gov", "ye": "gov",
 "za": "gov", "zm": "gov", "zw": "gov",
}

GOV_WORLD = {".%s.%s" % (v, k) for k, v in GOV_SLD.items()}
GOV_WORLD |= {".gov", ".gob", ".gouv", ".govt", ".gub", ".mil", ".gc", ".gv",
              ".admin", ".go", ".k12", ".muni", ".bund", ".gobierno"}

# ----------------------------------------------------------------------------
# wordlists
# ----------------------------------------------------------------------------

WORDLIST = """
www mail webmail smtp pop imap ns1 ns2 ns3 dns dns1 dns2 mx mx1 mx2 relay
ftp ftps sftp ssh vpn remote rdp citrix rdweb gateway sslvpn access sso idp
auth login signin account accounts portal extranet intranet internal admin
administrator adminpanel panel cpanel whm plesk webdisk webadmin console
dashboard manage management manager ops noc monitoring monitor stats metrics
grafana kibana prometheus zabbix nagios icinga netdata portainer rancher
k8s kubernetes docker registry harbor jenkins git gitlab gitea forgejo svn
jira confluence wiki docs doc help support kb knowledgebase ticket tickets crm
erp cms blog news press media cdn static assets img images files file upload
download downloads share shared drive cloud storage backup backups bak
db database mysql mssql postgres postgresql mongo mongodb redis memcached
elastic elasticsearch opensearch solr rabbitmq kafka trino presto hive spark
airflow superset metabase tableau api apis api1 api2 api-dev apigw gateway2
rest graphql soap wsdl rpc grpc app apps application mobile m web m2 test
testing tst dev develop development staging stage stg stag uat
preprod pre-prod ppd prod production prd live beta alpha demo sandbox lab
labs preview canary edge origin corp office owa exchange autodiscover
lync sip voip pbx asterisk mail2 smtp2 pop3 imap2 mx3 mx4
srv server server1 server2 host node node1 node2 vm esxi vcenter proxmox
ns4 ns5 dns3 slave master primary secondary
new old legacy v1 v2 v3 v4 tmp temp archive archives
proxy proxy1 haproxy nginx apache lb loadbalancer lb1 lb2 waf
pay payment payments billing invoice invoices shop store ecommerce cart
hr payroll finance accounting sales marketing seo analytics ga
status health check healthcheck ping uptime
school campus edu student students alumni library moodle dmoj nexus zimbra
gov gob municipal city council ministry
onat mes mined minag minrex inder hidro tsp inotu osri sipac citma
correo correos mailer mailhost lists listas boletines
intranet2 owa2 menu siral rectorado decanato secretaria despacho
roundcube squirrelmail nextcloud owncloud mattermost rocketchat glpi osticket
odoo vtiger espocrm suitecrm directus strapi ghost discourse bbpress buddypress
ldap ad dc dc1 dc2 adfs saml shibboleth cas radius tacacs
gitlab pages proxy2 cache cache1 search solr2 ldap2
""".split()

PERM_PREFIX = "dev staging stg test tst uat pre prod new old beta alpha demo lab sandbox vpn remote intranet extranet internal admin api app portal web static cdn backup tmp secure sso auth git jenkins jira grafana kibana".split()
PERM_SUFFIX = "dev staging stg test tst uat pre prod new old beta alpha demo lab sandbox vpn remote intranet internal admin api app portal web static cdn backup tmp secure sso auth git backup 2 1".split()

# ----------------------------------------------------------------------------
# fingerprints
# ----------------------------------------------------------------------------

TECH_HDR = [
    (r"nginx", "Nginx"), (r"apache/?([\d.]+)?", "Apache"),
    (r"microsoft-iis/?([\d.]+)?", "Microsoft IIS"), (r"openresty", "OpenResty"),
    (r"tomcat", "Apache Tomcat"), (r"wildfly", "WildFly"), (r"jboss", "JBoss"),
    (r"cloudflare", "Cloudflare"), (r"cloudfront", "CloudFront"),
    (r"akamai", "Akamai"), (r"gunicorn", "Gunicorn"), (r"werkzeug", "Flask"),
    (r"php/?([\d.]+)?", "PHP"), (r"asp\.net", "ASP.NET"),
    (r"x-powered-by:.*django", "Django"), (r"x-powered-by:.*laravel", "Laravel"),
    (r"x-powered-by:.*express", "Express"), (r"x-powered-by:.*next\.?js", "Next.js"),
    (r"x-generator:.*wordpress", "WordPress"), (r"x-generator:.*drupal", "Drupal"),
    (r"x-drupal", "Drupal"), (r"x-amz", "AWS"), (r"x-azure", "Azure"),
    (r"x-goog", "Google Cloud"), (r"x-fastly", "Fastly"), (r"x-vercel", "Vercel"),
]

TECH_COOKIE = [
    (r"phpsessid", "PHP"), (r"jsessionid", "Java"), (r"asp\.net_session", "ASP.NET"),
    (r"wordpress|wp-settings", "WordPress"), (r"drupal", "Drupal"),
    (r"joomla", "Joomla"), (r"laravel_session", "Laravel"),
    (r"ci_session", "CodeIgniter"), (r"__cfduid|__cf_bm", "Cloudflare"),
    (r"incap_ses|visid_incap", "Imperva"), (r"bigipserver", "F5 BIG-IP"),
    (r"keycloak", "Keycloak"), (r"zm_login_csrf|zimbra", "Zimbra"),
    (r"xsrf-token", "Laravel"), (r"moodle", "Moodle"),
]

TECH_BODY = [
    (r"wp-content|wp-includes", "WordPress"), (r"/sites/default/files", "Drupal"),
    (r"com_content|/media/system/js", "Joomla"), (r"_next/static", "Next.js"),
    (r"ng-version|ng-app", "Angular"), (r"data-reactroot|react\.production", "React"),
    (r"vue\.js|__vue__|data-v-", "Vue.js"), (r"jquery", "jQuery"),
    (r"googletagmanager|gtag\(", "Google Tag Manager"),
    (r"matomo|piwik", "Matomo"), (r"laravel", "Laravel"),
    (r"csrfmiddlewaretoken", "Django"), (r"__viewstate", "ASP.NET"),
    (r"kibana", "Kibana"), (r"grafana", "Grafana"), (r"portainer", "Portainer"),
    (r"jenkins", "Jenkins"), (r"gitlab", "GitLab"), (r"gitea", "Gitea"),
    (r"jira", "Jira"), (r"confluence", "Confluence"), (r"swagger-ui", "Swagger UI"),
    (r"phpmyadmin", "phpMyAdmin"), (r"adminer", "Adminer"), (r"minio", "MinIO"),
    (r"rabbitmq", "RabbitMQ"), (r"elasticsearch|_cluster/health", "Elasticsearch"),
    (r"trino|presto", "Trino/Presto"), (r"superset", "Superset"),
    (r"airflow", "Airflow"), (r"metabase", "Metabase"), (r"zabbix", "Zabbix"),
    (r"manager/html", "Tomcat Manager"), (r"solr", "Apache Solr"),
    (r"phpinfo", "phpinfo"), (r"directory listing for|index of /", "Dir listing"),
    (r"roundcube", "Roundcube"), (r"squirrelmail", "SquirrelMail"),
    (r"nextcloud", "Nextcloud"), (r"owncloud", "ownCloud"), (r"zimbra", "Zimbra"),
    (r"dmoj", "DMOJ Judge"), (r"moodle", "Moodle"), (r"chamilo", "Chamilo"),
    (r"nexus repository", "Sonatype Nexus"), (r"geonode", "GeoNode"),
    (r"telescope", "Laravel Telescope"), (r"_debugbar", "Laravel Debugbar"),
    (r"discourse", "Discourse"), (r"strapi", "Strapi"), (r"directus", "Directus"),
    (r"glpi", "GLPI"), (r"osticket", "osTicket"), (r"odoo", "Odoo"),
    (r"mattermost", "Mattermost"), (r"rocket\.chat", "Rocket.Chat"),
    (r"buddypress", "BuddyPress"), (r"bbpress", "bbPress"), (r"phpbb", "phpBB"),
    (r"vbulletin", "vBulletin"), (r"exchange|owa", "Exchange"),
]

TECH_META = [
    (r"generator\"?\s*content=\"?\s*wordpress", "WordPress"),
    (r"generator\"?\s*content=\"?\s*drupal", "Drupal"),
    (r"generator\"?\s*content=\"?\s*joomla", "Joomla"),
]

WAF_HDR = [
    (r"cloudflare|cf-ray", "Cloudflare"), (r"akamai|x-akamai", "Akamai"),
    (r"incap_ses|visid_incap|x-iinfo", "Imperva"),
    (r"bigip|big-ip|ts01", "F5 BIG-IP ASM"), (r"x-sucuri", "Sucuri"),
    (r"awselb|awsalb", "AWS ELB"), (r"x-amzn-requestid|x-amz-cf", "AWS WAF"),
    (r"x-azure-ref|x-msedge", "Azure Front Door"), (r"x-fastly", "Fastly"),
    (r"barra_counter_session|barracuda", "Barracuda"),
    (r"fortiweb|fortigate", "FortiWeb"), (r"citrix|netscaler", "Citrix"),
    (r"wallarm", "Wallarm"), (r"x-radware", "Radware"),
]

WAF_BODY = [
    (r"attention required! \| cloudflare", "Cloudflare"),
    (r"cloudflare ray id", "Cloudflare"), (r"incapsula incident id", "Imperva"),
    (r"the requested url was rejected", "F5 BIG-IP ASM"),
    (r"sucuri website firewall", "Sucuri"),
    (r"mod_security|not acceptable!", "ModSecurity"), (r"wordfence", "Wordfence"),
]

AUTH_PATHS = [
    "/login", "/signin", "/auth", "/sso", "/oauth2", "/adfs/ls/", "/cas/login",
    "/realms/master", "/.well-known/openid-configuration", "/saml/metadata",
    "/SAML/SSO", "/wp-login.php", "/admin", "/administrator", "/api/auth",
    "/user/login", "/users/sign_in", "/portal/login", "/cpanel", "/webmail",
    "/owa", "/autodiscover/autodiscover.xml", "/shibboleth", "/Shibboleth.sso/Metadata",
    "/adfs/FederationMetadata/2007-06/FederationMetadata.xml",
    "/idp/shibboleth", "/simplesaml/", "/idp/metadata",
]

AUTH_SIGS = [
    (r"openid-configuration|authorization_endpoint", "OpenID Connect"),
    (r"keycloak", "Keycloak"), (r"adfs|active directory federation", "ADFS"),
    (r"central authentication service", "CAS"),
    (r"shibboleth|SAMLRequest|SAMLResponse", "Shibboleth / SAML"),
    (r"okta", "Okta"), (r"auth0", "Auth0"),
    (r"login\.microsoftonline|msal", "Entra ID"),
    (r"ldap", "LDAP"), (r"two-factor|mfa|totp", "MFA"),
]

TAKEOVER = [
    (r"NoSuchBucket", "AWS S3"), (r"There isn't a GitHub Pages site here", "GitHub Pages"),
    (r"No such app", "Heroku"), (r"Fastly error: unknown domain", "Fastly"),
    (r"project not found", "Surge.sh"), (r"Repository not found", "Bitbucket"),
    (r"404 Web Site not found", "Azure App Service"),
    (r"Vercel.*DEPLOYMENT_NOT_FOUND", "Vercel"),
]

# ----------------------------------------------------------------------------
# secret patterns
# ----------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "high"),
    ("aws_secret_key", r"(?i)aws_?secret_?access_?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "critical"),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("stripe_secret", r"sk_(?:live|test)_[0-9a-zA-Z]{20,}", "critical"),
    ("sendgrid_key", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "high"),
    ("twilio_key", r"SK[0-9a-fA-F]{32}", "medium"),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", "high"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}", "high"),
    ("gitlab_token", r"glpat-[A-Za-z0-9\-_]{20,}", "high"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", "medium"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "critical"),
    ("laravel_app_key", r"APP_KEY\s*=\s*base64:[A-Za-z0-9+/=]{40,}", "critical"),
    ("bcrypt_hash", r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", "high"),
    ("db_url", r"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|ldap)://[^\s'\"<>]{6,200}", "high"),
    ("db_password", r"(?i)(?:DB_PASSWORD|MYSQL_PASSWORD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|DB_PASS|SMTP_PASS|SMTP_PASSWORD|PASS_OFFLINE|GEONODE_DATABASE_PASSWORD|LDAP_PASSWORD)\s*[=:]\s*['\"]?([^\s'\"\r\n]{1,80})", "critical"),
    ("api_token", r"(?i)(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|secret[_-]?key|bearer[_-]?token|check_token)\s*[=:]\s*['\"]?([A-Za-z0-9._\-]{12,160})", "high"),
    ("ngrok_token", r"(?i)ngrok[_-]?auth[_-]?token\s*[=:]\s*([A-Za-z0-9_\-]{20,})", "medium"),
    ("aes_key", r"(?i)(?:aes|encryption|crypto)[_\-]?(?:key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{2,80})", "high"),
    ("firebase_key", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{100,}", "medium"),
    ("facebook_app_id", r"fb:app_id\"?\s*content=\"?(\d{10,20})", "low"),
    ("git_commit", r"\b[0-9a-f]{40}\b", "low"),
    ("md5_hash", r"\b[a-f0-9]{32}\b", "low"),
]

SENSITIVE_PATHS = [
    "/.env", "/.env.example", "/.env.local", "/.env.prod", "/.env.production",
    "/.env.backup", "/.env.save", "/.env.old", "/.env.dev", "/.env.dist",
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/logs/HEAD",
    "/.git/packed-refs", "/.gitignore", "/.svn/entries", "/.svn/wc.db",
    "/.hg/hgrc", "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
    "/wp-config.php.save", "/wp-config.txt", "/config.php.bak", "/config.php~",
    "/configuration.php.bak", "/settings.py", "/local_settings.py",
    "/config.json", "/config.yml", "/docker-compose.yml", "/Dockerfile",
    "/composer.json", "/composer.lock", "/package.json", "/backup.zip",
    "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql", "/database.sql",
    "/www.zip", "/site.zip", "/.DS_Store", "/phpinfo.php", "/info.php",
    "/test.php", "/server-status", "/server-info", "/web.config", "/.htaccess",
    "/.htpasswd", "/id_rsa", "/swagger.json", "/openapi.json", "/v1/version",
    "/version", "/api/version", "/CHANGELOG.txt", "/README.md",
    "/core/CHANGELOG.txt", "/actuator/env", "/actuator/health",
    "/.well-known/jwks.json", "/jsonapi/user/user", "/administrator/",
    "/phpmyadmin/", "/adminer.php", "/manager/html", "/api/json",
    "/_cat/indices", "/_security/user", "/api/system/status", "/v1/statement",
    "/graphql", "/metrics", "/telescope", "/_debugbar/open",
    "/storage/logs/laravel.log", "/service/soap", "/wp-content/debug.log",
    "/users.csv", "/users.xlsx", "/contacts.csv", "/users.json",
    "/wp-json/", "/xmlrpc.php", "/user/autocomplete?q=a",
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

PATH_SEV = {
    "/.env": "critical", "/.env.local": "critical", "/.env.prod": "critical",
    "/.env.production": "critical", "/.env.backup": "critical",
    "/id_rsa": "critical", "/wp-config.php.bak": "critical",
    "/config.php.bak": "high", "/backup.sql": "high", "/db.sql": "high",
    "/dump.sql": "high", "/database.sql": "high", "/backup.zip": "high",
    "/.git/config": "high", "/actuator/env": "high", "/phpinfo.php": "medium",
    "/server-status": "medium", "/.svn/wc.db": "medium",
    "/storage/logs/laravel.log": "medium", "/wp-content/debug.log": "medium",
    "/telescope": "medium", "/users.csv": "medium", "/users.xlsx": "medium",
    "/composer.json": "low", "/swagger.json": "low", "/CHANGELOG.txt": "low",
}

# ----------------------------------------------------------------------------
# email constants
# ----------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+")

OBF_RE = re.compile(
    r"([A-Za-z0-9._%+\-]{2,64})\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\}|\s+at\s+)\s*"
    r"([A-Za-z0-9.\-]{2,64})\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}|\s+dot\s+)\s*"
    r"([A-Za-z]{2,12})", re.I)

CF_EMAIL_RE = re.compile(r'data-cfemail="([0-9a-fA-F]+)"')
CHARC_RE = re.compile(r"String\.fromCharCode\(([\d,\s]{4,200})\)")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
HREF_RE = re.compile(r"""(?:href|action|src)\s*=\s*["']([^"']+)["']""", re.I)
MAILTO_RE = re.compile(r"""mailto:([^"'?>\s]+)""", re.I)
GRAVATAR_MD5_RE = re.compile(r"secure\.gravatar\.com/avatar/([a-f0-9]{32})", re.I)
LOC_RE = re.compile(r"<loc>([^<]+)</loc>", re.I)
SAML_CONTACT_RE = re.compile(
    r"(?:EmailAddress|mailto:)[^>]*>?\s*(?:mailto:)?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
    re.I)

DOC_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".odt",
           ".ods", ".rtf", ".ppt", ".pptx")

HARVEST_PATHS = [
    "/contacto", "/contactenos", "/contact", "/contacts", "/contact-us",
    "/directorio", "/directory", "/funcionarios", "/personal", "/staff",
    "/equipo", "/team", "/organigrama", "/estructura", "/quienes-somos",
    "/about", "/nosotros", "/institucional", "/prensa", "/press",
    "/comunicacion", "/comunicaciones", "/comunicados", "/noticias", "/news",
    "/licitaciones", "/compras", "/contrataciones", "/concursos", "/empleo",
    "/trabaja-con-nosotros", "/rrhh", "/soporte", "/ayuda", "/servicios",
    "/tramites", "/atencion-ciudadana", "/ciudadano", "/oficinas",
    "/mapa-del-sitio", "/transparencia", "/acerca-de", "/miembros", "/members",
    "/usuarios", "/users", "/autoridades", "/directivos", "/planta",
    "/agenda", "/telefonos", "/extensiones", "/guia", "/red", "/docentes",
]

ROLE_MAILBOXES = """
info contacto contact prensa comunicacion comunicaciones compras contrataciones
licitaciones rrhh recursoshumanos soporte sistemas informatica tic seguridad
denuncias denuncia admin administrador webmaster postmaster hostmaster direccion
secretaria atencion atencionciudadana consultas servicios transparencia juridico
legal presupuesto contabilidad tesoreria estadisticas datos estadistica archivo
biblioteca capacitacion becas noticias eventos cultura deporte salud educacion
obras vivienda medioambiente ambiente energia minas agricultura transporte
aduana migracion policia bomberos defensa ejercito fiscalia tribunal registro
catastro protocolo ceremonial despacho subdireccion viceministro ministro
secretariado planificacion inversion cooperacion internacional hosting
atencionpoblacion atencion.usuarios atencionaclientes publico difusion
redaccion redac digital web comunicacionujc apoblacion presidencia rectorado
noreply no-reply mail correo oficina quejas reclamos consulta informes
""".split()

SECTOR_MAP = {
    "msp": "Health", "salud": "Health", "iess": "Social Security",
    "mes": "Education", "mined": "Education", "edu": "Education",
    "uclv": "University", "uh": "University", "cujae": "University",
    "minag": "Agriculture", "arcotel": "Telecom Regulator", "tsp": "Telecom",
    "etecsa": "Telecom", "enet": "Telecom", "icrt": "State Media",
    "bce": "Central Bank", "bc": "Central Bank", "cfn": "National Finance",
    "finanzas": "Finance", "presidencia": "Presidency", "anpp": "Legislature",
    "hidro": "Water/Energy", "aduana": "Customs", "seps": "Cooperatives",
    "bomberos": "Fire Service", "mit": "Transport", "minrex": "Foreign Affairs",
    "inder": "Sports", "onat": "Tax", "citma": "Science", "onei": "Statistics",
    "mtss": "Labour", "ics": "Cinema", "ujc": "Party Youth", "uneac": "Culture",
    "academiaciencias": "Science", "biocubafarma": "Pharma", "finlay": "Vaccines",
    "citmatel": "IT Company", "unicom": "Armed Forces", "ccffaa": "Armed Forces",
    "fae": "Air Force", "minint": "Interior", "minfar": "Defence",
    "upec": "Journalists", "trabajadores": "State Media", "acn": "State Media",
    "cubarte": "Culture", "palco": "Tourism", "amistur": "Tourism",
    "superbancos": "Regulator", "dmoj": "Education", "sld": "Health",
    "granma": "State Media", "juventudrebelde": "State Media", "gob": "Government",
}

GOV_SUFFIX_RE = re.compile(
    r"\.(gob|gov|gouv|govt|gub|mil|gc|gv|admin|go|k12|muni|bund|gobierno)\.[a-z]{2,}$", re.I)
GOV_PLAIN_RE = re.compile(r"\.(gov|gob|mil)$", re.I)

FREE_MAIL = {
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.es", "live.com",
    "icloud.com", "aol.com", "protonmail.com", "gmx.com", "mail.ru", "yandex.ru",
    "hotmail.es", "outlook.es",
}

GEO_COORD = [
    r"google\.[a-z.]+/maps/(?:place/)?[^\"'\s]*?@(-?\d{1,3}\.\d{4,}),(-?\d{1,3}\.\d{4,})",
    r"google\.[a-z.]+/maps\?q=(-?\d{1,3}\.\d{4,}),(-?\d{1,3}\.\d{4,})",
    r"maps\.google\.com/\?q=(-?\d{1,3}\.\d{4,}),(-?\d{1,3}\.\d{4,})",
    r"geo\.position\"?\s*content=\"?\s*(-?\d{1,3}\.\d{4,})\s*;\s*(-?\d{1,3}\.\d{4,})",
    r"geo:(-?\d{1,3}\.\d{4,}),(-?\d{1,3}\.\d{4,})",
]
GEO_ADDR = [
    r'og:street-address"?\s*content="([^"]{5,200})"',
    r'itemprop="streetAddress"[^>]*>([^<]{5,200})<',
    r'geo\.placename"?\s*content="([^"]{2,120})"',
]
TEL_RE = re.compile(r"tel:([+\d\s()\-\.]{6,30})")
PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
COMMIT_RE = re.compile(r"\b([0-9a-f]{40})\b")

SEC_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options", "referrer-policy",
]

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 636, 993, 995,
    1433, 1521, 3000, 3306, 3389, 5432, 5601, 5672, 5900, 6379, 8000, 8080,
    8081, 8443, 8888, 9000, 9090, 9200, 10000, 11211, 15672, 27017,
]

# ----------------------------------------------------------------------------
# domain parsing
# ----------------------------------------------------------------------------

SECOND_LEVEL_HINTS = {
    "gob", "com", "edu", "org", "net", "gov", "mil", "ac", "co", "or", "ne",
    "go", "gub", "gouv", "govt", "nic", "int", "sch", "ltd", "plc", "me",
    "in", "id", "web", "art", "nom", "med", "pro", "info", "biz", "gv",
    "k12", "muni", "asso", "presse", "fin", "res", "adm", "inf", "tur", "cip",
    "sld", "red", "bund", "admin", "gobierno",
}

def split_domain(raw):
    d = raw.strip().lower().rstrip(".")
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0].strip(".")
    if not d or "." not in d:
        return d, ""
    labels = [l for l in d.split(".") if l]
    n = len(labels)
    if n >= 3 and labels[-2] in SECOND_LEVEL_HINTS and len(labels[-1]) == 2:
        apex = ".".join(labels[-3:])
    elif n >= 2:
        apex = ".".join(labels[-2:])
    else:
        apex = d
    prefix = ".".join(labels[: max(0, n - len(apex.split(".")))])
    return apex, prefix

def derive_suffixes(apexes, world=False):
    out = set()
    for a in apexes:
        labels = a.split(".")
        if len(labels) < 2:
            continue
        tld = labels[-1]
        if len(tld) == 2:
            out.add("." + tld)
            for s in SECOND_LEVEL_HINTS:
                out.add("." + s + "." + tld)
            if tld in GOV_SLD:
                out.add(".%s.%s" % (GOV_SLD[tld], tld))
    if world:
        out |= GOV_WORLD
    return out

# ----------------------------------------------------------------------------
# DNS
# ----------------------------------------------------------------------------

class DNS:
    def __init__(self, nameservers=None, timeout=5.0, retries=2):
        self.timeout = timeout
        self.retries = retries
        self.resolver = None
        if HAVE_DNS:
            self.resolver = dns.resolver.Resolver(configure=True)
            if nameservers:
                self.resolver.nameservers = nameservers
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout * 2

    def query(self, host, rtype):
        for _ in range(self.retries + 1):
            try:
                if HAVE_DNS:
                    ans = self.resolver.resolve(host, rtype, raise_on_no_answer=False)
                    if ans.rrset is None:
                        return []
                    return [r.to_text().strip('"') for r in ans]
                return self._socket(host, rtype)
            except Exception:
                continue
        return []

    def _socket(self, host, rtype):
        if rtype == "A":
            return list({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
        return []

    def a(self, host):
        return self.query(host, "A")

    def aaaa(self, host):
        return self.query(host, "AAAA")

    def cname(self, host):
        return self.query(host, "CNAME")

    def resolve(self, host):
        ips, chain = set(), []
        cur = host
        for _ in range(6):
            cn = self.cname(cur)
            if not cn:
                break
            cur = cn[0].rstrip(".")
            chain.append(cur)
        ips.update(self.a(cur))
        ips.update(self.aaaa(cur))
        return sorted(ips), chain

    def txt(self, host):
        return self.query(host, "TXT")

    def mx(self, host):
        return self.query(host, "MX")

    def ns(self, host):
        return self.query(host, "NS")

    def soa(self, host):
        return self.query(host, "SOA")

    def caa(self, host):
        return self.query(host, "CAA")

    def axfr(self, host):
        records = []
        if not HAVE_DNS:
            return records
        for ns in self.ns(host):
            try:
                ip = self.a(ns.rstrip("."))
                if not ip:
                    continue
                z = dns.zone.from_xfr(dns.query.xfr(ip[0], host, timeout=10))
                for name, node in z.nodes.items():
                    for rd in node.rdatasets:
                        for r in rd:
                            records.append("%s %s %s" % (name, rd.rdtype, r))
                if records:
                    return records
            except Exception:
                continue
        return records

# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

class HttpClient:
    def __init__(self, timeout, proxy=None, verify=False):
        self.timeout = timeout
        self.proxy = proxy
        self.verify = verify
        self.local = threading.local()

    def _session(self):
        s = getattr(self.local, "s", None)
        if s is None:
            s = requests.Session()
            s.headers.update({
                "User-Agent": UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
                "Accept-Encoding": "gzip, deflate",
            })
            if self.proxy:
                s.proxies = {"http": self.proxy, "https": self.proxy}
            self.local.s = s
        return s

    def get(self, url, allow_redirects=True, stream=False, timeout=None, headers=None):
        return self._session().get(url, timeout=timeout or self.timeout,
                                   verify=self.verify, allow_redirects=allow_redirects,
                                   stream=stream, headers=headers)

    def post(self, url, data=None, json=None, timeout=None, headers=None,
             allow_redirects=True):
        return self._session().post(url, data=data, json=json,
                                    timeout=timeout or self.timeout,
                                    verify=self.verify, headers=headers,
                                    allow_redirects=allow_redirects)

    def body(self, resp, limit=250_000):
        try:
            chunks, total = [], 0
            for chunk in resp.iter_content(8192):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= limit:
                    break
            return b"".join(chunks).decode("utf-8", "replace")
        except Exception:
            try:
                return resp.text[:limit]
            except Exception:
                return ""

    def raw(self, url, limit=2_000_000, timeout=None):
        r = self.get(url, timeout=timeout or self.timeout, stream=True)
        data, total = [], 0
        for chunk in r.iter_content(16384):
            if not chunk:
                continue
            data.append(chunk)
            total += len(chunk)
            if total >= limit:
                break
        return r, b"".join(data)

# ----------------------------------------------------------------------------
# passive
# ----------------------------------------------------------------------------

class Passive:
    ALL = ["crt_sh", "hackertarget", "otx", "urlscan", "wayback", "rapiddns",
           "anubis", "certspotter", "subdomain_center", "bufferover",
           "mnemonic", "threatminer"]

    def __init__(self, http, limiter, timeout):
        self.http = http
        self.limiter = limiter
        self.timeout = timeout

    def _get_json(self, url, **kw):
        self.limiter.wait()
        r = self.http.get(url, timeout=self.timeout, **kw)
        if r.status_code != 200:
            raise RuntimeError("HTTP %s" % r.status_code)
        return r.json()

    def _get_text(self, url, **kw):
        self.limiter.wait()
        r = self.http.get(url, timeout=self.timeout, **kw)
        if r.status_code != 200:
            raise RuntimeError("HTTP %s" % r.status_code)
        return r.text

    def crt_sh(self, apex):
        out = set()
        for url in ("https://crt.sh/?q=%25.%s&output=json" % apex,
                    "https://crt.sh/?Identity=%25.%s&output=json" % apex):
            try:
                for row in self._get_json(url, timeout=max(self.timeout, 45)):
                    for f in ("name_value", "common_name"):
                        for n in str(row.get(f) or "").split("\n"):
                            out.add(n.strip().lower().lstrip("*."))
            except Exception:
                pass
        return out

    def hackertarget(self, apex):
        out = set()
        try:
            for line in self._get_text("https://api.hackertarget.com/hostsearch/?q=%s" % apex).splitlines():
                if "," in line:
                    out.add(line.split(",")[0].strip().lower())
        except Exception:
            pass
        return out

    def otx(self, apex):
        out = set()
        try:
            for row in self._get_json(
                    "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns" % apex
            ).get("passive_dns", []):
                if row.get("hostname"):
                    out.add(row["hostname"].lower())
        except Exception:
            pass
        return out

    def urlscan(self, apex):
        out = set()
        try:
            for row in self._get_json(
                    "https://urlscan.io/api/v1/search/?q=domain:%s&size=10000" % apex
            ).get("results", []):
                for k in ("domain", "apexDomain"):
                    if (row.get("page") or {}).get(k):
                        out.add(row["page"][k].lower())
        except Exception:
            pass
        return out

    def wayback(self, apex):
        out = set()
        try:
            txt = self._get_text(
                "http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text"
                "&collapse=urlkey&fl=original&limit=200000" % apex,
                timeout=max(self.timeout, 90))
            for line in txt.splitlines():
                h = urllib.parse.urlparse(line.strip()).hostname
                if h:
                    out.add(h.lower())
        except Exception:
            pass
        return out

    def rapiddns(self, apex):
        out = set()
        try:
            txt = self._get_text("https://rapiddns.io/subdomain/%s?full=1" % apex)
            for m in re.finditer(r">([A-Za-z0-9._\-]+\.%s)<" % re.escape(apex), txt):
                out.add(m.group(1).lower())
        except Exception:
            pass
        return out

    def anubis(self, apex):
        out = set()
        try:
            data = self._get_json("https://jldc.me/anubis/subdomains/%s" % apex)
            if isinstance(data, list):
                out.update(str(n).lower() for n in data)
        except Exception:
            pass
        return out

    def certspotter(self, apex):
        out = set()
        try:
            for row in self._get_json(
                    "https://api.certspotter.com/v1/issuances?domain=%s"
                    "&include_subdomains=true&expand=dns_names" % apex):
                out.update(n.lower().lstrip("*.") for n in row.get("dns_names", []))
        except Exception:
            pass
        return out

    def subdomain_center(self, apex):
        out = set()
        try:
            data = self._get_json("https://api.subdomain.center/?domain=%s" % apex)
            if isinstance(data, list):
                out.update(str(n).lower() for n in data)
        except Exception:
            pass
        return out

    def bufferover(self, apex):
        out = set()
        try:
            data = self._get_json("https://dns.bufferover.run/dns?q=.%s" % apex)
            for key in ("FDNS_A", "RDNS"):
                for row in (data.get(key) or []):
                    parts = str(row).split(",")
                    if len(parts) > 1:
                        out.add(parts[-1].strip().lower())
        except Exception:
            pass
        return out

    def mnemonic(self, apex):
        out = set()
        try:
            for row in self._get_json(
                    "https://api.mnemonic.no/pdns/v3/%s?limit=10000" % apex).get("data", []):
                if row.get("queryName"):
                    out.add(row["queryName"].lower().rstrip("."))
        except Exception:
            pass
        return out

    def threatminer(self, apex):
        out = set()
        try:
            for n in self._get_json(
                    "https://api.threatminer.org/v2/domain.php?q=%s&rt=5" % apex).get("results", []) or []:
                out.add(str(n).lower())
        except Exception:
            pass
        return out

    def chaos(self, apex, key):
        out = set()
        if not key:
            return out
        try:
            self.limiter.wait()
            r = self.http.get("https://dns.projectdiscovery.io/dns/%s/subdomains" % apex,
                              headers={"Authorization": key}, timeout=self.timeout)
            if r.status_code == 200:
                out.update(("%s.%s" % (n, apex)).lower() for n in r.json().get("subdomains", []))
        except Exception:
            pass
        return out

# ----------------------------------------------------------------------------
# discovery: commoncrawl, wayback paths, search engines, pgp, saml
# ----------------------------------------------------------------------------

class Discovery:
    def __init__(self, http, limiter, timeout):
        self.http = http
        self.limiter = limiter
        self.timeout = timeout
        self.cc_index = None

    def _cc_index(self):
        if self.cc_index is not None:
            return self.cc_index
        self.cc_index = ""
        try:
            self.limiter.wait()
            r = self.http.get("https://index.commoncrawl.org/collinfo.json",
                              timeout=self.timeout)
            if r.status_code == 200:
                info = r.json()
                if info:
                    self.cc_index = info[0]["id"]
        except Exception:
            pass
        return self.cc_index

    def commoncrawl(self, apex, limit=3000):
        out = set()
        idx = self._cc_index()
        if not idx:
            return out
        try:
            self.limiter.wait()
            r = self.http.get(
                "https://index.commoncrawl.org/%s-index?url=*.%s/*&output=json&limit=%d"
                % (idx, apex, limit), timeout=max(self.timeout, 60))
            if r.status_code != 200:
                return out
            for line in r.text.splitlines():
                try:
                    out.add(json.loads(line)["url"])
                except Exception:
                    continue
        except Exception:
            pass
        return out

    def wayback_paths(self, apex, limit=2000):
        out = set()
        try:
            self.limiter.wait()
            r = self.http.get(
                "http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original"
                "&collapse=urlkey&limit=%d&filter=original:.*(contact|contacto|contactenos|"
                "directorio|directory|staff|equipo|funcionario|personal|organigrama|"
                "transparencia|prensa|comunicacion|rrhh|empleo|licitacion|autoridad|"
                "miembro|usuario|member|user).*" % (apex, limit),
                timeout=max(self.timeout, 90))
            if r.status_code == 200:
                out.update(x.strip() for x in r.text.splitlines() if x.strip())
        except Exception:
            pass
        return out

    def search_engines(self, apex):
        queries = [
            'site:%s "@%s"' % (apex, apex),
            '"@%s"' % apex,
            'site:%s contacto correo electronico' % apex,
            'site:%s "@gmail.com"' % apex,
            'site:%s filetype:pdf "@%s"' % (apex, apex),
            'site:%s directorio funcionarios' % apex,
            'site:%s "correo institucional"' % apex,
        ]
        urls, emails = set(), set()
        engines = [
            "https://html.duckduckgo.com/html/?q=",
            "https://www.bing.com/search?q=",
            "https://www.mojeek.com/search?q=",
            "https://search.brave.com/search?q=",
            "https://lite.duckduckgo.com/lite/?q=",
        ]
        for q in queries:
            enc = urllib.parse.quote_plus(q)
            for base in engines:
                try:
                    self.limiter.wait()
                    r = self.http.get(base + enc, timeout=max(self.timeout, 20))
                    if r.status_code != 200:
                        continue
                    for e in extract_emails(r.text):
                        emails.add(e)
                    for m in re.finditer(r"uddg=([^&\"]+)", r.text):
                        urls.add(urllib.parse.unquote(m.group(1)))
                    for m in re.finditer(r'href="(https?://[^"]+)"', r.text):
                        if apex in m.group(1):
                            urls.add(m.group(1))
                except Exception:
                    continue
        return urls, emails

    def pgp_keyserver(self, domain):
        """keys.openpgp.org by-domain returns UIDs containing emails."""
        out = set()
        try:
            self.limiter.wait()
            r = self.http.get(
                "https://keys.openpgp.org/vks/v1/by-domain/%s" % domain,
                timeout=max(self.timeout, 20))
            if r.status_code == 200:
                for e in extract_emails(r.text):
                    out.add(e)
        except Exception:
            pass
        try:
            self.limiter.wait()
            r = self.http.get(
                "https://keyserver.ubuntu.com/pks/lookup?op=index&search=%s&options=mr"
                % urllib.parse.quote(domain), timeout=max(self.timeout, 20))
            if r.status_code == 200:
                for e in extract_emails(r.text):
                    out.add(e)
        except Exception:
            pass
        return out

# ----------------------------------------------------------------------------
# LDAP (raw BER, anonymous)
# ----------------------------------------------------------------------------

def _ber_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def _ber(tag, payload):
    return bytes([tag]) + _ber_len(len(payload)) + payload

def _ber_int(n):
    if n == 0:
        return _ber(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _ber(0x02, b)

def _ber_str(s):
    return _ber(0x04, s.encode())

def ldap_anon_enum(host, base, timeout=8, limit=400):
    """Anonymous bind + subtree search for mail/cn/uid. Returns emails."""
    out = set()
    try:
        s = socket.create_connection((host, 389), timeout=timeout)
    except Exception:
        return out
    try:
        s.settimeout(timeout)
        bind = _ber(0x30, _ber_int(1) + _ber(0x60, _ber_int(3) + _ber_str("") + _ber(0x80, b"")))
        s.sendall(bind)
        try:
            s.recv(4096)
        except Exception:
            pass
        filt = _ber(0xA3, _ber_str("objectClass") + _ber_str("person"))
        attrs = _ber(0x30, _ber_str("mail") + _ber_str("cn") + _ber_str("uid"))
        search = _ber(0x30, _ber_int(2) + _ber(
            0x63,
            _ber_str(base) + _ber(0x0A, b"\x02") + _ber(0x0A, b"\x00") +
            _ber_int(limit) + _ber_int(timeout) + _ber(0x01, b"\x00") +
            filt + attrs))
        s.sendall(search)
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline and len(buf) < 3_000_000:
            try:
                chunk = s.recv(65536)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
            if b"\x42\x00" in buf[-64:]:
                break
        for e in extract_emails(buf.decode("latin-1", "replace")):
            out.add(e)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return out

# ----------------------------------------------------------------------------
# SMTP VRFY / EXPN
# ----------------------------------------------------------------------------

def smtp_vrfy(mx_host, name, timeout=8):
    try:
        with socket.create_connection((mx_host, 25), timeout=timeout) as s:
            s.settimeout(timeout)
            f = s.makefile("rwb", buffering=0)

            def cmd(line):
                f.write((line + "\r\n").encode())
                buf = b""
                while True:
                    c = f.readline()
                    if not c:
                        break
                    buf += c
                    if len(c) < 4 or c[3:4] != b"-":
                        break
                return buf.decode("utf-8", "replace")

            cmd("EHLO venice-recon.local")
            v = cmd("VRFY %s" % name)
            x = cmd("EXPN %s" % name)
            cmd("QUIT")
            return v, x
    except Exception:
        return "", ""

# ----------------------------------------------------------------------------
# wildcard
# ----------------------------------------------------------------------------

def wildcard_probe(dns, apex, depth=3):
    rnd = lambda: "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    ips = set()
    probes = ["%s.%s" % (rnd(), apex) for _ in range(depth)]
    for p in probes:
        try:
            got, _ = dns.resolve(p)
            ips.update(got)
        except Exception:
            pass
    return ips, probes

# ----------------------------------------------------------------------------
# extraction
# ----------------------------------------------------------------------------

def decode_cfemail(hexstr):
    try:
        key = int(hexstr[:2], 16)
        return "".join(chr(int(hexstr[i:i + 2], 16) ^ key)
                       for i in range(2, len(hexstr), 2))
    except Exception:
        return ""

def decode_charcodes(text):
    out = []
    for m in CHARC_RE.finditer(text):
        try:
            nums = [int(x) for x in m.group(1).split(",") if x.strip()]
            out.append("".join(chr(n) for n in nums if 0 < n < 0x110000))
        except Exception:
            pass
    return " ".join(out)

def extract_emails(text):
    found = set()
    if not text:
        return found
    for h in CF_EMAIL_RE.findall(text):
        e = decode_cfemail(h)
        if e:
            found.add(e)
    found.update(decode_charcodes(text).split())
    t = (text.replace("&#64;", "@").replace("&commat;", "@").replace("%40", "@")
             .replace("&#046;", ".").replace("&#46;", ".").replace("&period;", "."))
    for m in MAILTO_RE.findall(t):
        found.add(urllib.parse.unquote(m.split("?")[0]))
    for m in EMAIL_RE.findall(t):
        found.add(m)
    for m in OBF_RE.finditer(t):
        found.add("%s@%s.%s" % (m.group(1), m.group(2), m.group(3)))
    clean = set()
    for e in found:
        e = e.strip().strip(".,;:<>()[]\"'").lower().replace(" ", "")
        if EMAIL_RE.fullmatch(e) and len(e) <= 120:
            local, _, dom = e.rpartition("@")
            if local and "." in dom:
                clean.add(e)
    return clean

def extract_secrets(text, cap=400):
    out, seen = [], set()
    for name, rx, sev in SECRET_PATTERNS:
        for m in re.finditer(rx, text):
            val = m.group(0)[:300]
            if (name, val) in seen:
                continue
            seen.add((name, val))
            out.append({"type": name, "severity": sev, "value": val,
                        "context": text[max(0, m.start() - 60):m.end() + 60]
                        .replace("\n", " ")[:220]})
            if len(out) >= cap:
                return out
    return out

def extract_geo(text):
    geo = {"coords": [], "addresses": [], "places": [], "phones": []}
    for rx in GEO_COORD:
        for m in re.finditer(rx, text, re.I):
            try:
                lat, lon = float(m.group(1)), float(m.group(2))
            except Exception:
                continue
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                v = "%.7f,%.7f" % (lat, lon)
                if v not in geo["coords"]:
                    geo["coords"].append(v)
    for rx in GEO_ADDR:
        for m in re.finditer(rx, text, re.I):
            v = re.sub(r"\s+", " ", m.group(1)).strip()
            if v and v not in geo["addresses"]:
                geo["addresses"].append(v)
    for m in TEL_RE.findall(text):
        v = m.strip()
        if v and v not in geo["phones"]:
            geo["phones"].append(v)
    return {k: v[:25] for k, v in geo.items() if v}

def is_gov_email(email):
    dom = email.rpartition("@")[2]
    return bool(GOV_SUFFIX_RE.search(dom) or GOV_PLAIN_RE.search(dom))

def sector_of(*labels):
    for l in labels:
        for k, v in SECTOR_MAP.items():
            if l == k or l.startswith(k) or k in l:
                return v
    return ""

def doc_text(data, ext):
    if ext == ".pdf":
        for mod in ("pypdf", "PyPDF2"):
            try:
                m = __import__(mod, fromlist=["PdfReader"])
                rd = m.PdfReader(io.BytesIO(data))
                txt = "\n".join((p.extract_text() or "") for p in rd.pages[:40])
                try:
                    meta = rd.metadata or {}
                    for k in ("/Author", "/Creator", "/Producer", "/Title"):
                        if meta.get(k):
                            txt += "\nAUTHOR: %s" % meta.get(k)
                except Exception:
                    pass
                return txt
            except Exception:
                pass
        return data.decode("latin-1", "replace")
    if ext in (".docx", ".xlsx", ".pptx", ".odt", ".ods"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                parts = []
                for n in z.namelist():
                    if n.endswith(".xml"):
                        parts.append(z.read(n).decode("utf-8", "replace"))
                return "\n".join(parts)[:1_500_000]
        except Exception:
            return ""
    return data.decode("utf-8", "replace")[:1_500_000]

# ----------------------------------------------------------------------------
# gravatar
# ----------------------------------------------------------------------------

def gravatar_md5(email):
    return hashlib.md5(email.strip().lower().encode()).hexdigest()

def gravatar_sha256(email):
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()

def gravatar_exists(http, limiter, md5, timeout=6):
    try:
        limiter.wait()
        r = http.get("https://secure.gravatar.com/avatar/%s?d=404&s=40" % md5,
                     timeout=timeout, allow_redirects=True, stream=True)
        r.close()
        return r.status_code == 200
    except Exception:
        return False

def local_candidates(username, display=""):
    cands = set()
    u = (username or "").strip().lower()
    if u:
        cands.add(u)
    parts = [p for p in re.split(r"[.\-_@\s]+", u) if p]
    dparts = [p for p in re.split(r"[.\-_\s,]+", (display or "").lower())
              if p.isalpha() and len(p) > 1]
    first = parts[0] if parts else ""
    last = parts[-1] if len(parts) > 1 else ""
    if len(dparts) >= 2:
        first, last = dparts[0], dparts[-1]
    if first and last and first != last:
        cands.update({
            "%s.%s" % (first, last), "%s%s" % (first, last),
            "%s_%s" % (first, last), "%s-%s" % (first, last),
            "%s.%s" % (first[0], last), "%s%s" % (first[0], last),
            "%s.%s" % (last, first), "%s%s" % (last[0], first),
            "%s.%s" % (first, last[0]), "%s_%s" % (first[0], last),
            "%s-%s" % (first[0], last), "%s%s" % (last, first[0]),
        })
        if len(last) > 3:
            cands.add("%s.%s" % (first, last[:3]))
    if first:
        cands.add(first)
        cands.add("%s1" % first)
    if last:
        cands.add(last)
    if u and "-" in u:
        cands.add(u.replace("-", "."))
        cands.add(u.replace("-", ""))
    return {c for c in cands if 1 < len(c) < 64}

def smtp_verify(mx_host, from_addr, to_addr, timeout=10):
    try:
        with socket.create_connection((mx_host, 25), timeout=timeout) as s:
            s.settimeout(timeout)
            f = s.makefile("rwb", buffering=0)

            def cmd(line):
                f.write((line + "\r\n").encode())
                buf = b""
                while True:
                    c = f.readline()
                    if not c:
                        break
                    buf += c
                    if len(c) < 4 or c[3:4] != b"-":
                        break
                return buf.decode("utf-8", "replace")

            cmd("EHLO venice-recon.local")
            cmd("MAIL FROM:<%s>" % from_addr)
            resp = cmd("RCPT TO:<%s>" % to_addr)
            cmd("QUIT")
            code = int(resp[:3]) if resp[:3].isdigit() else 0
            return code, resp.strip()[:200]
    except Exception as e:
        return 0, str(e)

# ----------------------------------------------------------------------------
# harvester
# ----------------------------------------------------------------------------

class Harvester:
    def __init__(self, http, limiter, timeout, apexes, args, mx_hosts, suffixes, discovery):
        self.http = http
        self.limiter = limiter
        self.timeout = timeout
        self.apexes = apexes
        self.apex = apexes[0]
        self.args = args
        self.mx_hosts = mx_hosts
        self.suffixes = suffixes
        self.discovery = discovery
        self.scope_exact = [s.strip().lower() for s in (args.scope or "").split(",") if s.strip()]

    def _get(self, url, limit=400_000):
        self.limiter.wait()
        r = self.http.get(url, timeout=self.timeout, stream=True, allow_redirects=True)
        return r, self.http.body(r, limit)

    def _scope_ok(self, email):
        dom = email.rpartition("@")[2]
        for a in self.apexes:
            if dom == a or dom.endswith("." + a):
                return True
        for s in self.scope_exact:
            if dom == s or dom.endswith("." + s):
                return True
        for suf in self.suffixes:
            if dom.endswith(suf):
                return True
        if self.args.allow_free_mail and dom in FREE_MAIL:
            return True
        return False

    def collect(self, host, base_url):
        result = {"host": host, "emails": {}, "users": {}, "user_display": {},
                  "docs": [], "notes": [], "gravatar": {}, "exposures": [],
                  "secrets": [], "geo": {}, "versions": [], "commits": [],
                  "internal_ips": [], "tls_pii": {}, "git": {}, "extra": {},
                  "metadata": [], "ldap": [], "vrfy": []}
        pages = [self.args.harvest_max_pages]
        docs = [self.args.harvest_max_docs]
        seen = set()
        soft = {"len": None, "hash": None}

        def add_email(e, source):
            e = e.strip().lower()
            if EMAIL_RE.fullmatch(e) and self._scope_ok(e):
                result["emails"].setdefault(e, set()).add(source)

        def add_user(u, source, display=None):
            u = str(u).strip()[:80]
            if not u or len(u) < 2:
                return
            result["users"].setdefault(u, set()).add(source)
            if display:
                result["user_display"][u] = str(display)[:80]

        def scan_text(body, source, url=""):
            for e in extract_emails(body):
                add_email(e, source)
            if self.args.secrets:
                for s in extract_secrets(body):
                    s["source"] = url or source
                    result["secrets"].append(s)
            if self.args.geo:
                for k, vals in extract_geo(body).items():
                    result["geo"].setdefault(k, [])
                    for v in vals:
                        if v not in result["geo"][k]:
                            result["geo"][k].append(v)
            for ip in PRIVATE_IP_RE.findall(body):
                if ip not in result["internal_ips"]:
                    result["internal_ips"].append(ip)

        def grab(url, source, depth=0):
            if url in seen or pages[0] <= 0:
                return
            seen.add(url)
            pages[0] -= 1
            try:
                r, body = self._get(url)
            except Exception as e:
                result["notes"].append("%s: %s" % (url, e))
                return
            scan_text(body, source, url)
            for href in HREF_RE.findall(body)[:800]:
                full = urllib.parse.urljoin(r.url, href)
                low = urllib.parse.urlparse(full).path.lower()
                if low.endswith(DOC_EXT):
                    result["docs"].append(full)
                elif depth < 2 and re.search(
                        r"contact|contacto|directorio|directory|staff|equipo|"
                        r"funcionario|personal|organigrama|transparencia|"
                        r"prensa|comunicacion|rrhh|empleo|licitacion|usuario|"
                        r"miembro|autoridad|member|user", low):
                    grab(full, "page:" + os.path.basename(low)[:40], depth + 1)

        # TLS PII
        tls = self.args._tls.get(host, {}) or {}
        for f in ("subject", "issuer"):
            for k, v in (tls.get(f) or {}).items():
                if "@" in str(v):
                    result["tls_pii"].setdefault("emails", []).append(str(v))
                    add_email(str(v), "tls-cert")
                if k.upper() in ("CN", "OU", "O", "L", "ST"):
                    result["tls_pii"].setdefault(k, []).append(str(v))
        for san in (tls.get("san") or []):
            if "@" in san:
                add_email(san, "tls-san")

        # well-known text files
        for path, src in (("/.well-known/security.txt", "security.txt"),
                          ("/security.txt", "security.txt"),
                          ("/humans.txt", "humans.txt"),
                          ("/robots.txt", "robots.txt")):
            try:
                self.limiter.wait()
                r, body = self._get(urllib.parse.urljoin(base_url, path), 80_000)
                if r.status_code == 200:
                    scan_text(body, src)
                    if src == "robots.txt":
                        for m in re.finditer(r"(?i)sitemap:\s*(\S+)", body):
                            sm = urllib.parse.urljoin(base_url, m.group(1))
                            try:
                                _, smb = self._get(sm, 600_000)
                                for loc in LOC_RE.findall(smb):
                                    low = loc.lower()
                                    if low.endswith(DOC_EXT):
                                        result["docs"].append(loc)
                                    elif re.search(r"contact|directorio|staff|funcionario|"
                                                   r"transparencia|organigrama|author|user", low):
                                        grab(loc, "sitemap")
                            except Exception:
                                pass
            except Exception:
                pass

        # SAML / federation metadata contacts
        if self.args.saml_meta:
            self._saml(base_url, add_email, result)

        # Exchange autodiscover
        if self.args.autodiscover:
            self._autodiscover(base_url, add_email, result)

        for path in HARVEST_PATHS:
            if pages[0] <= 0:
                break
            grab(urllib.parse.urljoin(base_url, path), "page" + path)

        if self.args.secrets:
            self._exposures(host, base_url, result, scan_text, soft)

        if self.args.wp_users:
            self._wp(host, base_url, add_email, add_user, result)
        if self.args.xmlrpc:
            self._xmlrpc(base_url, add_user, result)
        if self.args.drupal_users:
            self._drupal(base_url, add_email, add_user)
        if self.args.joomla:
            self._joomla(base_url, add_email, add_user)
        if self.args.api_users:
            self._apis(base_url, add_email, add_user, result)
        if self.args.graphql:
            self._graphql(base_url, add_user)
        if self.args.wp_login_probe:
            self._wp_login(base_url, result)

        if self.args.ldap:
            self._ldap(host, result, add_email)
        if self.args.vrfy and self.mx_hosts:
            self._vrfy(result)

        if self.args.gravatar and result["users"]:
            self._gravatar(host, result, add_email)

        uniq = list(dict.fromkeys(result["docs"]))
        for d in uniq[: docs[0]]:
            ext = os.path.splitext(urllib.parse.urlparse(d).path)[1].lower()
            try:
                self.limiter.wait()
                r, data = self.http.raw(d, 3_000_000, timeout=max(self.timeout, 20))
                if r.status_code != 200 or not data:
                    continue
                text = doc_text(data, ext)
                scan_text(text, "doc:" + ext, d)
                for m in re.finditer(r"(?i)(?:AUTHOR|Creator|lastModifiedBy)[:=]\s*(.{2,80})", text):
                    val = m.group(1).strip()
                    if val and len(val) < 80:
                        result["metadata"].append({"doc": d, "value": val})
                        add_user(val.replace(" ", "."), "doc-metadata")
            except Exception:
                continue
        result["docs"] = uniq[:200]

        if self.args.rdap:
            for a in self.apexes[:3]:
                try:
                    self.limiter.wait()
                    r = self.http.get("https://rdap.org/domain/%s" % a, timeout=self.timeout)
                    if r.status_code == 200:
                        for e in extract_emails(r.text):
                            add_email(e, "rdap")
                except Exception:
                    pass

        return result

    # ---- exposure scan with soft-404 calibration ----

    def _calibrate(self, base_url, soft):
        rnd = "venice-%s" % "".join(random.choices(string.ascii_lowercase, k=10))
        for p in ("/%s.html" % rnd, "/%s" % rnd, "/.env.%s" % rnd):
            try:
                self.limiter.wait()
                r = self.http.get(urllib.parse.urljoin(base_url, p), timeout=self.timeout,
                                  stream=True, allow_redirects=False)
                body = self.http.body(r, 60_000)
                r.close()
                if r.status_code in (200, 404):
                    soft["len"] = len(body)
                    soft["hash"] = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
                    return
            except Exception:
                continue

    def _exposures(self, host, base_url, result, scan_text, soft):
        if soft["len"] is None:
            self._calibrate(base_url, soft)

        def one(path):
            url = urllib.parse.urljoin(base_url, path)
            try:
                self.limiter.wait()
                r = self.http.get(url, timeout=self.timeout, stream=True,
                                  allow_redirects=False)
                if r.status_code not in (200, 206):
                    r.close()
                    return None
                body = self.http.body(r, 200_000)
                r.close()
            except Exception:
                return None
            if not body:
                return None
            h = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
            if soft["hash"] and h == soft["hash"]:
                return None
            if soft["len"] and abs(len(body) - soft["len"]) <= 40 and len(body) < 2000:
                if re.search(r"not found|404", body[:400], re.I):
                    return None
            sev = PATH_SEV.get(path, "info")
            found = extract_secrets(body)
            for f in found:
                f["source"] = url
                result["secrets"].append(f)
                if SEV_ORDER[f["severity"]] < SEV_ORDER[sev]:
                    sev = f["severity"]
            for e in extract_emails(body):
                scan_text(e, "exposure:" + path, url)
            if path == "/.git/config":
                remote = re.search(r"url\s*=\s*(\S+)", body)
                if remote:
                    result["git"]["remote"] = remote.group(1)
            for c in COMMIT_RE.findall(body)[:5]:
                if c not in result["commits"]:
                    result["commits"].append(c)
            return {"path": path, "url": url, "status": r.status_code, "size": len(body),
                    "severity": sev, "secrets": len(found), "snippet": body[:600]}

        with cf.ThreadPoolExecutor(max_workers=24) as ex:
            for rec in ex.map(one, SENSITIVE_PATHS):
                if rec:
                    result["exposures"].append(rec)

    # ---- SAML / federation metadata ----

    def _saml(self, base_url, add_email, result):
        paths = ["/saml/metadata", "/SAML/SSO", "/Shibboleth.sso/Metadata",
                 "/idp/shibboleth", "/idp/metadata", "/simplesaml/saml2/idp/metadata.php",
                 "/adfs/FederationMetadata/2007-06/FederationMetadata.xml",
                 "/FederationMetadata/2007-06/FederationMetadata.xml",
                 "/.well-known/saml-metadata", "/metadata.xml"]
        for p in paths:
            try:
                self.limiter.wait()
                r, body = self._get(urllib.parse.urljoin(base_url, p), 400_000)
                if r.status_code != 200:
                    continue
                hits = 0
                for m in SAML_CONTACT_RE.finditer(body):
                    add_email(m.group(1), "saml-metadata")
                    hits += 1
                for e in extract_emails(body):
                    add_email(e, "saml-metadata")
                    hits += 1
                if hits:
                    result["extra"].setdefault("saml", []).append(p)
            except Exception:
                continue

    def _autodiscover(self, base_url, add_email, result):
        body = ('<?xml version="1.0" encoding="utf-8"?><Autodiscover '
                'xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/'
                'responseschema/2006a"><Request><EMailAddress>%s</EMailAddress>'
                '<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/'
                'autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>'
                '</Request></Autodiscover>' % ("probe@" + self.apex))
        for p in ("/autodiscover/autodiscover.xml", "/Autodiscover/Autodiscover.xml"):
            try:
                self.limiter.wait()
                r = self.http.post(urllib.parse.urljoin(base_url, p), data=body,
                                   timeout=self.timeout,
                                   headers={"Content-Type": "text/xml"})
                if r.status_code not in (200, 401):
                    continue
                text = self.http.body(r, 200_000)
                for e in extract_emails(text):
                    add_email(e, "autodiscover")
                for m in re.finditer(r"<Server>([^<]+)</Server>", text):
                    result["extra"].setdefault("exchange_servers", []).append(m.group(1))
                if text:
                    result["extra"].setdefault("autodiscover", []).append(p)
            except Exception:
                continue

    # ---- WordPress ----

    def _wp(self, host, base_url, add_email, add_user, result):
        apis = ["/wp-json/wp/v2/users?per_page=100&_fields=id,slug,name,description,avatar_urls",
                "/?rest_route=/wp/v2/users&per_page=100",
                "/wp-json/wp/v2/users?per_page=100"]
        confirmed = False
        for api in apis:
            for page in range(1, self.args.wp_pages + 1):
                sep = "&" if "?" in api else "?"
                url = urllib.parse.urljoin(base_url, "%s%spage=%d" % (api, sep, page))
                try:
                    self.limiter.wait()
                    r, body = self._get(url)
                    if r.status_code != 200:
                        break
                    data = json.loads(body)
                    if not isinstance(data, list) or not data:
                        break
                    confirmed = True
                    for u in data:
                        disp = u.get("name")
                        if u.get("slug"):
                            add_user(u["slug"], "wp-rest", disp)
                        if disp:
                            add_user(disp, "wp-rest-name", disp)
                        for av in (u.get("avatar_urls") or {}).values():
                            m = GRAVATAR_MD5_RE.search(str(av))
                            if m:
                                result["gravatar"].setdefault(u.get("slug", "?"),
                                                              {})["md5"] = m.group(1)
                        for e in extract_emails(u.get("description") or ""):
                            add_email(e, "wp-rest-bio")
                    if len(data) < 100:
                        break
                except Exception:
                    break

        if confirmed:
            # route dump -> find custom user endpoints
            try:
                self.limiter.wait()
                r, body = self._get(urllib.parse.urljoin(base_url, "/wp-json/"), 500_000)
                if r.status_code == 200:
                    for route in (json.loads(body).get("routes") or {}):
                        if re.search(r"user|member|people|staff|contact|author", route, re.I):
                            result["extra"].setdefault("wp_routes", []).append(route)
            except Exception:
                pass
            if self.args.wp_search:
                for ch in "abcdefghijklmnopqrstuvwxyz":
                    try:
                        self.limiter.wait()
                        r, body = self._get(urllib.parse.urljoin(
                            base_url, "/wp-json/wp/v2/users?per_page=100&search=%s" % ch))
                        if r.status_code != 200:
                            continue
                        for u in json.loads(body):
                            if u.get("slug"):
                                add_user(u["slug"], "wp-search", u.get("name"))
                    except Exception:
                        continue
            for path in ("/wp-json/wp/v2/comments?per_page=100",
                         "/wp-json/wp/v2/pages?per_page=100&_fields=content,link",
                         "/wp-json/wp/v2/posts?per_page=100&_fields=content,link",
                         "/wp-json/wp/v2/media?per_page=100&_fields=link,media_details"):
                try:
                    self.limiter.wait()
                    r, body = self._get(urllib.parse.urljoin(base_url, path), 900_000)
                    if r.status_code != 200:
                        continue
                    for e in extract_emails(body):
                        add_email(e, "wp-rest-content")
                    try:
                        for item in json.loads(body):
                            if item.get("link"):
                                result["docs"].append(item["link"])
                    except Exception:
                        pass
                except Exception:
                    continue
            for path in ("/wp-sitemap-users-1.xml", "/wp-sitemap.xml",
                         "/sitemap_index.xml", "/author-sitemap.xml"):
                try:
                    self.limiter.wait()
                    r, body = self._get(urllib.parse.urljoin(base_url, path), 300_000)
                    if r.status_code != 200:
                        continue
                    for loc in LOC_RE.findall(body):
                        m = re.search(r"/author/([^/?#<]+)", loc)
                        if m:
                            add_user(urllib.parse.unquote(m.group(1)), "wp-sitemap")
                except Exception:
                    continue
            for path in ("/members/", "/activity/", "/forums/users/",
                         "/wp-json/buddypress/v1/members?per_page=100"):
                try:
                    self.limiter.wait()
                    r, body = self._get(urllib.parse.urljoin(base_url, path), 500_000)
                    if r.status_code != 200:
                        continue
                    for e in extract_emails(body):
                        add_email(e, "buddypress")
                    try:
                        for m in json.loads(body):
                            if isinstance(m, dict):
                                for k in ("slug", "name", "user_login", "display_name"):
                                    if m.get(k):
                                        add_user(m[k], "buddypress")
                    except Exception:
                        for m in re.finditer(r'/members/([^/"?#]+)/', body):
                            add_user(m.group(1), "buddypress")
                except Exception:
                    continue

        for n in range(1, self.args.wp_authors + 1):
            try:
                self.limiter.wait()
                r = self.http.get(urllib.parse.urljoin(base_url, "/?author=%d" % n),
                                  timeout=self.timeout, allow_redirects=True, stream=True)
                final = r.url
                body = self.http.body(r, 150_000)
                if r.status_code != 200:
                    continue
                m = re.search(r"/author/([^/?#]+)", final)
                if m:
                    add_user(urllib.parse.unquote(m.group(1)), "wp-author")
                for e in extract_emails(body):
                    add_email(e, "wp-author-page")
            except Exception:
                continue

        for path in ("/feed/", "/comments/feed/", "/?feed=rss2"):
            try:
                self.limiter.wait()
                r, body = self._get(urllib.parse.urljoin(base_url, path), 300_000)
                if r.status_code != 200:
                    continue
                for e in extract_emails(body):
                    add_email(e, "wp-feed")
                for m in re.findall(r"<dc:creator><!\[CDATA\[([^\]]+)\]\]></dc:creator>", body):
                    add_user(m, "wp-feed-author")
            except Exception:
                continue

    def _wp_login(self, base_url, result):
        url = urllib.parse.urljoin(base_url, "/wp-login.php")
        confirmed = []
        for u in list(result["users"])[: self.args.wp_login_max]:
            try:
                self.limiter.wait()
                r = self.http.post(url, data={
                    "log": u, "pwd": "zz-%d" % random.randint(1000, 9999),
                    "wp-submit": "Log In", "testcookie": "1"}, timeout=self.timeout)
                if "incorrect" in self.http.body(r, 60_000).lower():
                    confirmed.append(u)
            except Exception:
                continue
        if confirmed:
            result["extra"]["wp_login_confirmed"] = confirmed

    # ---- XML-RPC ----

    def _xmlrpc(self, base_url, add_user, result):
        url = urllib.parse.urljoin(base_url, "/xmlrpc.php")
        try:
            self.limiter.wait()
            r = self.http.post(url, data=(
                '<?xml version="1.0"?><methodCall><methodName>system.listMethods'
                '</methodName><params></params></methodCall>'),
                timeout=self.timeout, headers={"Content-Type": "text/xml"})
            if r.status_code != 200:
                return
            body = self.http.body(r, 200_000)
            if "wp.getUsersBlogs" not in body:
                return
            result["extra"].setdefault("xmlrpc", []).append("wp.getUsersBlogs")
        except Exception:
            return
        for u in list(result["users"])[: self.args.xmlrpc_max]:
            try:
                self.limiter.wait()
                payload = (
                    '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs'
                    '</methodName><params><param><value>%s</value></param>'
                    '<param><value>zz-%d</value></param></params></methodCall>'
                    % (u, random.randint(1000, 9999)))
                r = self.http.post(url, data=payload, timeout=self.timeout,
                                   headers={"Content-Type": "text/xml"})
                body = self.http.body(r, 60_000)
                if "isAdmin" in body or "blogid" in body:
                    result["extra"].setdefault("xmlrpc_confirmed", []).append(u)
            except Exception:
                continue

    # ---- Drupal ----

    def _drupal(self, base_url, add_email, add_user):
        try:
            self.limiter.wait()
            r, body = self._get(urllib.parse.urljoin(base_url, "/user/autocomplete?q=a"), 200_000)
            if r.status_code == 200:
                try:
                    for item in json.loads(body):
                        val = item.get("value") or item.get("label")
                        if val:
                            add_user(val, "drupal-autocomplete")
                except Exception:
                    for m in re.findall(r'"value"\s*:\s*"([^"]+)"', body):
                        add_user(m, "drupal-autocomplete")
        except Exception:
            pass
        for path in ("/jsonapi/user/user?page[limit]=50", "/jsonapi/user/user"):
            try:
                self.limiter.wait()
                r, body = self._get(urllib.parse.urljoin(base_url, path), 900_000)
                if r.status_code != 200:
                    continue
                for rec in (json.loads(body).get("data") or []):
                    attrs = rec.get("attributes") or {}
                    for k in ("name", "display_name"):
                        if attrs.get(k):
                            add_user(attrs[k], "drupal-jsonapi", attrs.get("display_name"))
                    if attrs.get("mail"):
                        add_email(attrs["mail"], "drupal-jsonapi")
            except Exception:
                continue
        for n in range(1, self.args.drupal_users + 1):
            try:
                self.limiter.wait()
                r, body = self._get(urllib.parse.urljoin(base_url, "/user/%d" % n), 150_000)
                if r.status_code != 200:
                    continue
                m = TITLE_RE.search(body)
                if m:
                    name = re.sub(r"\s*\|\s*.*$", "", m.group(1)).strip()
                    if name and not re.search(r"page not found|not found", name, re.I):
                        add_user(name, "drupal-user")
                for e in extract_emails(body):
                    add_email(e, "drupal-user-page")
            except Exception:
                continue

    # ---- Joomla ----

    def _joomla(self, base_url, add_email, add_user):
        paths = ["/?option=com_users&view=users", "/index.php?option=com_users&view=users",
                 "/index.php?option=com_contact&view=category&id=1",
                 "/index.php?option=com_contact&view=featured",
                 "/component/users/?view=users"]
        for p in paths:
            try:
                self.limiter.wait()
                r, body = self._get(urllib.parse.urljoin(base_url, p), 400_000)
                if r.status_code != 200:
                    continue
                for e in extract_emails(body):
                    add_email(e, "joomla-contact")
                for m in re.findall(r'class="[^"]*(?:contact-name|user-name)[^"]*"[^>]*>([^<]{2,60})<', body):
                    add_user(m, "joomla-contact")
            except Exception:
                continue

    # ---- GraphQL ----

    def _graphql(self, base_url, add_user):
        q = {"query": "{__schema{types{name fields{name}}}}"}
        for p in ("/graphql", "/api/graphql", "/v1/graphql"):
            try:
                self.limiter.wait()
                r = self.http.post(urllib.parse.urljoin(base_url, p), json=q,
                                   timeout=self.timeout,
                                   headers={"Content-Type": "application/json"})
                if r.status_code != 200:
                    continue
                body = self.http.body(r, 200_000)
                if "__schema" not in body:
                    continue
                for m in re.finditer(r'"name"\s*:\s*"(users?|members?|people|staff|contacts?)"', body, re.I):
                    add_user("graphql:" + m.group(1), "graphql-type")
            except Exception:
                continue

    # ---- panels / APIs ----

    ENDPOINTS = [
        ("/api/v2/users?page=1", "dmoj"),
        ("/api/users", "generic-users"),
        ("/api/v1/users", "generic-users"),
        ("/api/v1/users?per_page=100", "generic-users"),
        ("/api/users/search?perpage=100", "grafana"),
        ("/api/org/users", "grafana"),
        ("/api/v4/users?per_page=100", "gitlab"),
        ("/explore/users", "gitlab-web"),
        ("/api/v1/users/search?q=a&limit=50", "gitea"),
        ("/explore/users", "gitea-web"),
        ("/rest/api/2/user/picker?query=a", "jira"),
        ("/rest/api/2/users?limit=200", "jira"),
        ("/asynchPeople/api/json", "jenkins"),
        ("/people/", "jenkins-web"),
        ("/api/json?tree=users[fullName,absoluteUrl]", "jenkins"),
        ("/_security/user", "elasticsearch"),
        ("/ocs/v1.php/cloud/users", "nextcloud"),
        ("/api/v4/users?per_page=200", "mattermost"),
        ("/api/v1/users.list", "rocketchat"),
        ("/api/users/search?ps=100", "sonar"),
        ("/service/rest/v1/security/users", "nexus"),
        ("/api/v1/accounts", "mastodon"),
        ("/admin/realms/master/users?max=100", "keycloak"),
        ("/api/v1/security/users/", "superset"),
        ("/api/user/", "metabase"),
        ("/api/users", "portainer"),
        ("/api/users", "minio"),
        ("/api/users", "rabbitmq"),
        ("/api/v1/users", "airflow"),
        ("/api/v1/workspaces", "generic"),
        ("/api/v1/members", "generic"),
        ("/api/v1/people", "generic"),
        ("/api/people", "generic"),
        ("/api/users/list", "generic"),
        ("/wp-json/wp/v2/users", "wordpress"),
        ("/api/auth/users", "generic"),
        ("/user/list", "generic"),
        ("/users/list", "generic"),
        ("/api/v1/staff", "generic"),
        ("/directory_items.json", "discourse"),
        ("/api/users/0/items", "directus"),
        ("/admin/users", "strapi"),
        ("/apirest.php/User", "glpi"),
        ("/api/v1/users/", "espocrm"),
        ("/index.php?module=Users&action=index", "suitecrm"),
        ("/api/v1/users", "osticket"),
        ("/user/profile.php", "moodle"),
        ("/api/v1/users", "chamilo"),
        ("/api/v1/catalog/nodes", "consul"),
        ("/api/v1/namespaces", "k8s"),
        ("/v2/_catalog", "docker-registry"),
    ]

    def _apis(self, base_url, add_email, add_user, result):
        for path, label in self.ENDPOINTS:
            try:
                self.limiter.wait()
                r, body = self._get(urllib.parse.urljoin(base_url, path), 900_000)
                if r.status_code != 200:
                    continue
                for e in extract_emails(body):
                    add_email(e, label)
                try:
                    data = json.loads(body)
                except Exception:
                    data = None
                for rec in self._walk(data):
                    for key in ("email", "mail", "emailAddress", "mailAddress", "correo"):
                        if isinstance(rec.get(key), str) and "@" in rec[key]:
                            add_email(rec[key], label)
                    disp = None
                    for key in ("fullName", "displayName", "display_name", "nombre"):
                        if isinstance(rec.get(key), str):
                            disp = rec[key]
                    for key in ("username", "login", "slug", "name", "uid", "usuario"):
                        if isinstance(rec.get(key), str) and 1 < len(rec[key]) < 80:
                            add_user(rec[key], label, disp)
                    m = GRAVATAR_MD5_RE.search(str(rec))
                    if m:
                        result["gravatar"].setdefault(str(rec.get("username", "?")),
                                                      {})["md5"] = m.group(1)
            except Exception:
                continue

    @staticmethod
    def _walk(data, depth=0):
        if depth > 4:
            return
        if isinstance(data, list):
            for item in data[:500]:
                yield from Harvester._walk(item, depth + 1)
        elif isinstance(data, dict):
            yield data
            for v in list(data.values())[:60]:
                if isinstance(v, (dict, list)):
                    yield from Harvester._walk(v, depth + 1)

    # ---- LDAP ----

    def _ldap(self, host, result, add_email):
        for h in (host, "ldap." + self.apex, "dc." + self.apex):
            for base in (self.apex, "dc=" + self.apex.replace(".", ",dc=")):
                try:
                    hits = ldap_anon_enum(h, base, timeout=min(self.timeout, 8))
                except Exception:
                    hits = set()
                if hits:
                    for e in hits:
                        add_email(e, "ldap-anon")
                    result["ldap"].append({"host": h, "base": base, "count": len(hits)})
                    log("LDAP anon on %s: %d addresses" % (h, len(hits)), "OK")
                    return

    def _vrfy(self, result):
        if not self.mx_hosts:
            return
        mx = self.mx_hosts[0]
        for u in list(result["users"])[: self.args.vrfy_max]:
            try:
                v, x = smtp_vrfy(mx, u, timeout=min(self.timeout, 8))
            except Exception:
                continue
            for line, kind in ((v, "vrfy"), (x, "expn")):
                if not line:
                    continue
                if line[:3] in ("250", "252") and "@" in line:
                    for e in extract_emails(line):
                        result["emails"].setdefault(e, set()).add(kind)
                        result["vrfy"].append({"user": u, "kind": kind, "response": line[:120]})

    def _gravatar(self, host, result, add_email):
        domains = [host] + self.apexes + self.scope_exact
        if self.args.allow_free_mail:
            domains += ["gmail.com", "hotmail.com"]
        domains = list(dict.fromkeys(d for d in domains if d))[:6]
        budget = [self.args.gravatar_max]

        def check(user):
            hits = []
            disp = result["user_display"].get(user, "")
            for local in local_candidates(user, disp):
                for dom in domains:
                    if budget[0] <= 0:
                        return user, hits
                    budget[0] -= 1
                    email = "%s@%s" % (local, dom)
                    md5 = gravatar_md5(email)
                    if gravatar_exists(self.http, self.limiter, md5):
                        hits.append({"email": email, "md5": md5,
                                     "sha256": gravatar_sha256(email)})
            return user, hits

        with cf.ThreadPoolExecutor(max_workers=10) as ex:
            for user, hits in ex.map(check, list(result["users"])[:200]):
                for h in hits:
                    result["gravatar"].setdefault(user, {}).update(h)
                    add_email(h["email"], "gravatar-confirmed")

    def verify(self, emails):
        if not self.mx_hosts or not emails:
            return {}
        out = {}
        mx = self.mx_hosts[0]
        from_addr = "postmaster@%s" % self.apex
        rnd = "zz-%s@%s" % ("".join(random.choices(string.ascii_lowercase, k=12)), self.apex)
        code, _ = smtp_verify(mx, from_addr, rnd)
        catch_all = code in (250, 251)
        for e in emails[: self.args.verify_max]:
            code, msg = smtp_verify(mx, from_addr, e)
            out[e] = {"code": code, "accepted": code in (250, 251),
                      "catch_all": catch_all, "response": msg}
        return out

# ----------------------------------------------------------------------------
# prober
# ----------------------------------------------------------------------------

class Prober:
    def __init__(self, http, limiter, timeout):
        self.http = http
        self.limiter = limiter
        self.timeout = timeout

    def tls(self, host):
        info = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert() or {}
                    if cert:
                        info["subject"] = dict(x[0] for x in cert.get("subject", []))
                        info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                        info["san"] = [v for k, v in cert.get("subjectAltName", [])]
        except Exception as e:
            info["error"] = str(e)
        return info

    def probe(self, host):
        res = {"host": host, "url": None, "status": None, "title": None,
               "server": None, "headers": {}, "tech": [], "waf": [], "auth": [],
               "emails": [], "tls": None, "takeover": [], "notes": []}
        scheme = None
        for s in ("https", "http"):
            try:
                self.limiter.wait()
                r = self.http.get("%s://%s" % (s, host), allow_redirects=False,
                                  timeout=self.timeout, stream=True)
                r.close()
                scheme = s
                break
            except Exception:
                continue
        if not scheme:
            res["notes"].append("no HTTP response")
            return res
        res["url"] = "%s://%s" % (scheme, host)
        if scheme == "https":
            res["tls"] = self.tls(host)
        try:
            self.limiter.wait()
            r = self.http.get(res["url"], timeout=self.timeout, stream=True)
            body = self.http.body(r, 250_000)
        except Exception as e:
            res["notes"].append("fetch error: %s" % e)
            return res
        res["status"] = r.status_code
        res["server"] = r.headers.get("server")
        res["headers"] = {k.lower(): v for k, v in r.headers.items()}
        m = TITLE_RE.search(body)
        if m:
            res["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:300]
        blob = "\n".join("%s: %s" % (k, v) for k, v in res["headers"].items())
        ck = " ".join(c.name for c in r.cookies)
        tech_names = {n for _, n in TECH_HDR + TECH_COOKIE + TECH_BODY + TECH_META}
        for table, hay in ((TECH_HDR, blob), (TECH_COOKIE, ck), (TECH_BODY, body),
                           (TECH_META, body), (WAF_HDR, blob), (WAF_BODY, body)):
            for rx, name in table:
                if name in res["tech"] or name in res["waf"]:
                    continue
                if re.search(rx, hay, re.I):
                    (res["tech"] if name in tech_names else res["waf"]).append(name)
        for rx, name in TAKEOVER:
            if re.search(rx, body, re.I):
                res["takeover"].append(name)
        for rx, name in AUTH_SIGS:
            if re.search(rx, blob + " " + body.lower(), re.I) and name not in res["auth"]:
                res["auth"].append(name)
        res["emails"] = sorted(extract_emails(body))[:200]
        return res

# ----------------------------------------------------------------------------
# ports
# ----------------------------------------------------------------------------

def scan_ports(host, ports, timeout=3.0, workers=64):
    out = []

    def one(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((host, p)) == 0:
                return p
        finally:
            s.close()
        return None

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(one, ports):
            if r:
                out.append({"port": r, "banner": ""})
    return out

# ----------------------------------------------------------------------------
# report
# ----------------------------------------------------------------------------

class Report:
    def __init__(self, apexes):
        self.apexes = apexes
        self.apex = apexes[0]
        self.data = {
            "meta": {"tool": "venice-recon", "version": VERSION, "apexes": apexes,
                     "started": now_iso(), "finished": None, "args": {}},
            "dns": {}, "wildcard": {}, "subdomains": [], "hosts": {},
            "technologies": {}, "waf": {}, "auth": {}, "ports": {},
            "takeover": [], "zone_transfer": [], "exposures": [], "secrets": [],
            "gravatar": {}, "geo": {}, "commits": [], "internal_ips": [],
            "git": {}, "tls_pii": {}, "stats": {},
            "harvest": {"emails": [], "gov_emails": [], "users": [],
                        "domain_breakdown": {}, "sectors": {}, "patterns": {},
                        "candidates": [], "role_probes": [], "mail_infra": [],
                        "docs": [], "verification": {}, "metadata": [],
                        "ldap": [], "vrfy": [], "stats": {}},
        }

    def finalise(self):
        self.data["meta"]["finished"] = now_iso()
        tech, waf, auth = defaultdict(list), defaultdict(list), defaultdict(list)
        for h, d in self.data["hosts"].items():
            for t in d.get("tech", []):
                tech[t].append(h)
            for w in d.get("waf", []):
                waf[w].append(h)
            for a in d.get("auth", []):
                auth[a].append(h)
        self.data["technologies"] = dict(sorted(tech.items(), key=lambda x: -len(x[1])))
        self.data["waf"] = dict(sorted(waf.items(), key=lambda x: -len(x[1])))
        self.data["auth"] = dict(sorted(auth.items(), key=lambda x: -len(x[1])))
        self.data["exposures"].sort(key=lambda r: SEV_ORDER.get(r.get("severity", "info"), 9))
        self.data["secrets"].sort(key=lambda r: SEV_ORDER.get(r.get("severity", "info"), 9))
        sev = defaultdict(int)
        for r in self.data["exposures"] + self.data["secrets"]:
            sev[r.get("severity", "info")] += 1
        h = self.data["harvest"]
        self.data["stats"] = {
            "apexes": len(self.apexes),
            "subdomains_found": len(self.data["subdomains"]),
            "hosts_live": len(self.data["hosts"]),
            "exposures": len(self.data["exposures"]), "secrets": len(self.data["secrets"]),
            "critical": sev["critical"], "high": sev["high"],
            "harvested_emails": len(h["emails"]), "gov_emails": len(h["gov_emails"]),
            "harvested_users": len(h["users"]),
            "gravatar_hashes": sum(1 for v in self.data["gravatar"].values() if v.get("md5")),
            "gravatar_confirmed": sum(1 for v in self.data["gravatar"].values() if v.get("email")),
            "candidate_emails": len(h["candidates"]), "domains": len(h["domain_breakdown"]),
            "ldap_hits": len(h["ldap"]), "vrfy_hits": len(h["vrfy"]),
        }

    def write(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, default=str)

    def write_emails(self, base):
        h = self.data["harvest"]
        os.makedirs(os.path.dirname(os.path.abspath(base)), exist_ok=True)
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump({"gov_emails": h["gov_emails"], "emails": h["emails"],
                       "users": h["users"], "gravatar": self.data["gravatar"],
                       "breakdown": h["domain_breakdown"], "candidates": h["candidates"],
                       "verification": h["verification"], "ldap": h["ldap"],
                       "vrfy": h["vrfy"]}, f, indent=2, default=str)
        with open(base + ".csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["email", "domain", "gov", "sector", "sources", "host",
                        "smtp_code", "smtp_accepted"])
            for row in h["emails"]:
                v = h["verification"].get(row["email"], {})
                w.writerow([row["email"], row["domain"], row["gov"], row["sector"],
                            ";".join(row["sources"]), row["host"],
                            v.get("code", ""), v.get("accepted", "")])
        with open(base + "_gravatar.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["username", "md5", "sha256", "confirmed_email"])
            for u, v in self.data["gravatar"].items():
                w.writerow([u, v.get("md5", ""), v.get("sha256", ""), v.get("email", "")])
        with open(base + "_users.txt", "w", encoding="utf-8") as f:
            for u in h["users"]:
                f.write(u["user"] + "\n")

    def markdown(self):
        s, h = self.data["stats"], self.data["harvest"]
        L = ["# Recon report — %s" % ", ".join(self.apexes), "",
             "Generated: %s" % self.data["meta"]["finished"], "",
             "| Metric | Value |", "|---|---|"]
        for k, v in s.items():
            L.append("| %s | %s |" % (k, v))
        if h["gov_emails"]:
            L += ["", "## Government emails (%d)" % len(h["gov_emails"]), "",
                  "| Domain | Count |", "|---|---|"]
            for d, c in sorted(h["domain_breakdown"].items(), key=lambda x: -x[1]):
                L.append("| %s | %d |" % (d, c))
            L += ["", "### Addresses", ""]
            for e in h["gov_emails"][:1000]:
                L.append("- %s" % e["email"])
        if h["users"]:
            L += ["", "## Users (%d)" % len(h["users"]), ""]
            for u in h["users"][:800]:
                L.append("- %s (%s)" % (u["user"], ", ".join(u["sources"])))
        if self.data["gravatar"]:
            L += ["", "## Gravatar hashes", ""]
            for u, v in self.data["gravatar"].items():
                L.append("- %s → `%s` %s" % (u, v.get("md5", ""), v.get("email", "")))
        return "\n".join(L)

# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def load_targets(args):
    raw = list(args.targets or [])
    if args.targets_file and os.path.isfile(args.targets_file):
        with open(args.targets_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if line:
                    raw.append(line)
    if args.country:
        for c in [x.strip().lower() for x in args.country.split(",") if x.strip()]:
            if c in GOV_SLD:
                raw.append("%s.%s" % (GOV_SLD[c], c))
    out = []
    for t in raw:
        t = t.strip().lower().rstrip("/")
        if t and t not in out:
            out.append(t)
    return out

def load_wordlist(path):
    words = set(WORDLIST)
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                w = line.strip().lower()
                if w and not w.startswith("#"):
                    words.add(w)
    return sorted(words)

def in_scope(name, apexes, suffixes):
    name = name.strip().lower().rstrip(".")
    if not name or " " in name:
        return False
    for a in apexes:
        if name == a or name.endswith("." + a):
            return True
    for s in suffixes:
        if name.endswith(s):
            return True
    return False

def apply_aggressive(args):
    for flag in ("deep", "permute", "zone_transfer", "wp_users", "wp_search",
                 "drupal_users", "api_users", "wp_login_probe", "rdap",
                 "role_probe", "verify_emails", "secrets", "gravatar", "geo",
                 "auto_suffix", "allow_free_mail", "include_non_gov", "se",
                 "cc", "harvest", "xmlrpc", "ldap", "vrfy", "autodiscover",
                 "saml_meta", "joomla", "graphql"):
        setattr(args, flag, True)
    args.threads = max(args.threads, 120)
    args.rps = max(args.rps, 200.0)
    args.harvest_max_pages = max(args.harvest_max_pages, 250)
    args.harvest_max_docs = max(args.harvest_max_docs, 100)
    args.wp_authors = max(args.wp_authors, 800)
    args.drupal_users = max(args.drupal_users, 80)
    args.wp_pages = max(args.wp_pages, 40)
    args.gravatar_max = max(args.gravatar_max, 6000)
    args.verify_max = max(args.verify_max, 1500)
    args.vrfy_max = max(args.vrfy_max, 200)
    args.xmlrpc_max = max(args.xmlrpc_max, 100)
    args.port_threads = max(args.port_threads, 40)
    return args

def run(args):
    global QUIET
    QUIET = args.quiet
    if args.aggressive:
        args = apply_aggressive(args)

    targets = load_targets(args)
    if not targets:
        log("no targets", "ERR")
        return 2
    apexes = []
    for t in targets:
        a, _ = split_domain(t)
        if args.apex:
            a = args.apex.strip().lower().rstrip(".")
        if a and a not in apexes:
            apexes.append(a)

    suffixes = derive_suffixes(apexes, world=args.gov_world)
    banner()
    log("apexes  : %s" % ", ".join(apexes), "OK")
    if args.gov_world:
        log("gov-world scope: %d suffixes" % len(suffixes))
    log("threads=%d rps=%.0f aggressive=%s" % (args.threads, args.rps, args.aggressive))

    limiter = RateLimiter(args.rps)
    http = HttpClient(args.timeout, proxy=args.proxy)
    nameservers = [n.strip() for n in (args.resolvers or "").split(",") if n.strip()]
    dns = DNS(nameservers, timeout=args.timeout)
    report = Report(apexes)
    report.data["meta"]["args"] = {k: v for k, v in vars(args).items()}
    discovery = Discovery(http, limiter, args.timeout)

    candidates = set(targets)
    for a in apexes:
        candidates.add(a)
        report.data["dns"][a] = {"a": dns.a(a), "mx": dns.mx(a), "ns": dns.ns(a),
                                 "txt": dns.txt(a), "soa": dns.soa(a)}
        if args.zone_transfer:
            report.data["zone_transfer"].extend(dns.axfr(a))

    wc_all = set()
    for a in apexes:
        ips, probes = wildcard_probe(dns, a)
        report.data["wildcard"][a] = {"detected": bool(ips), "ips": sorted(ips)}
        wc_all |= ips
        if ips:
            log("wildcard on %s" % a, "WRN")

    if not args.no_passive:
        sources = [s for s in Passive.ALL if s not in (args.skip_sources or [])]
        passive = Passive(http, limiter, max(args.timeout, 30))
        log("passive: %d sources x %d apexes" % (len(sources), len(apexes)))

        def call(pair):
            src, apex = pair
            try:
                return src, apex, getattr(passive, src)(apex)
            except Exception:
                return src, apex, set()

        with cf.ThreadPoolExecutor(max_workers=min(16, len(sources) * len(apexes) or 1)) as ex:
            for src, apex, got in ex.map(call, [(s, a) for a in apexes for s in sources]):
                clean = {n for n in got if in_scope(n, apexes, suffixes)}
                if clean:
                    log("%-16s %-24s %5d" % (src, apex, len(clean)), "OK")
                candidates |= clean

        if args.cc:
            for a in apexes:
                for u in discovery.commoncrawl(a):
                    h = urllib.parse.urlparse(u).hostname
                    if h and in_scope(h, apexes, suffixes):
                        candidates.add(h.lower())
        if args.se:
            log("search engines", "INF")
            for a in apexes:
                urls, emails = discovery.search_engines(a)
                report.data["harvest"].setdefault("se", [])
                report.data["harvest"]["se"].extend(e for e in emails if in_scope(e, apexes, suffixes))
                for u in urls:
                    h = urllib.parse.urlparse(u).hostname
                    if h and in_scope(h, apexes, suffixes):
                        candidates.add(h.lower())
                for e in discovery.pgp_keyserver(a):
                    report.data["harvest"].setdefault("pgp", [])
                    if in_scope(e, apexes, suffixes):
                        report.data["harvest"]["pgp"].append(e)

    if not args.no_brute:
        words = load_wordlist(args.wordlist)
        log("brute force %d labels" % len(words))

        def brute(pair):
            w, a = pair
            host = "%s.%s" % (w, a)
            ips, _ = dns.resolve(host)
            return host if ips else None

        with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for r in ex.map(brute, [(w, a) for a in apexes for w in words]):
                if r:
                    candidates.add(r)

    if args.permute and candidates:
        base = set()
        for c in candidates:
            for a in apexes:
                if c.endswith("." + a):
                    base.add(c[: -len("." + a)].replace(".", "-"))
        base = {b for b in base if b and len(b) < 60}
        perms = set()
        for b in sorted(base)[:args.permute_seed]:
            for p in PERM_PREFIX[:24]:
                perms.add("%s-%s" % (p, b))
            for s in PERM_SUFFIX[:20]:
                perms.add("%s-%s" % (b, s))
        perms = sorted(p for p in perms if len(p) < 90)[:args.permute_max]

        def perm(p):
            for a in apexes:
                host = "%s.%s" % (p, a)
                ips, _ = dns.resolve(host)
                if ips:
                    return host
            return None

        with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for r in ex.map(perm, perms):
                if r:
                    candidates.add(r)

    log("resolving %d candidates" % len(candidates))
    resolved = {}

    def resolve_one(h):
        try:
            return h, dns.resolve(h)
        except Exception:
            return h, ([], [])

    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for h, (ips, chain) in ex.map(resolve_one, sorted(candidates)):
            if not ips:
                continue
            if wc_all and set(ips).issubset(wc_all) and h not in apexes:
                continue
            resolved[h] = {"ips": ips}

    report.data["subdomains"] = sorted(resolved)
    log("resolved %d hosts" % len(resolved), "OK")

    if not args.no_ports:
        ports = [int(p) for p in args.ports.split(",")] if args.ports else DEFAULT_PORTS

        def do_ports(h):
            return h, scan_ports(h, ports, timeout=min(args.timeout, 4), workers=48)

        with cf.ThreadPoolExecutor(max_workers=args.port_threads) as ex:
            for h, res in ex.map(do_ports, sorted(resolved)):
                if res:
                    report.data["ports"][h] = res

    prober = Prober(http, limiter, args.timeout)
    tlist = sorted(resolved)[:args.max_hosts] if args.max_hosts else sorted(resolved)
    log("probing %d hosts" % len(tlist))
    tls_map = {}
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for res in ex.map(lambda h: prober.probe(h), tlist):
            report.data["hosts"][res["host"]] = res
            if res.get("tls"):
                tls_map[res["host"]] = res["tls"]
            if res.get("status"):
                log("%-50s %s" % (res["host"], res["status"]), "OK")

    if args.harvest:
        args._tls = tls_map
        mx_hosts = []
        for a in apexes:
            for rec in (report.data["dns"].get(a, {}).get("mx") or []):
                host = rec.split()[-1].rstrip(".") if " " in rec else rec.rstrip(".")
                if host:
                    mx_hosts.append(host)
            for c in ("mail." + a, "smtp." + a):
                try:
                    if dns.a(c):
                        mx_hosts.append(c)
                except Exception:
                    pass
        mx_hosts = list(dict.fromkeys(mx_hosts))
        report.data["harvest"]["mail_infra"] = [
            h for h in resolved if re.search(r"(^|\.)(mail|smtp|imap|pop|webmail|owa|exchange|autodiscover|mx|zimbra|ldap)", h, re.I)]

        live = [h for h, d in report.data["hosts"].items() if d.get("status") and d.get("url")]
        live.sort(key=lambda h: (0 if re.search(r"www|portal|intranet|admin|git|nexus", h) else 1, h))
        if args.harvest_hosts:
            live = live[:args.harvest_hosts]
        log("harvesting %d hosts" % len(live))

        harvester = Harvester(http, limiter, args.timeout, apexes, args, mx_hosts,
                              suffixes, discovery)

        def harvest_one(h):
            try:
                return harvester.collect(h, report.data["hosts"][h]["url"])
            except Exception as e:
                return {"host": h, "emails": {}, "users": {}, "user_display": {},
                        "docs": [], "notes": [str(e)], "gravatar": {}, "exposures": [],
                        "secrets": [], "geo": {}, "versions": [], "commits": [],
                        "internal_ips": [], "tls_pii": {}, "git": {}, "extra": {},
                        "metadata": [], "ldap": [], "vrfy": []}

        agg, users = {}, {}
        with cf.ThreadPoolExecutor(max_workers=max(8, args.threads // 2)) as ex:
            for r in ex.map(harvest_one, live):
                for e, srcs in r["emails"].items():
                    agg.setdefault(e, {"sources": set(), "hosts": set()})
                    agg[e]["sources"].update(srcs)
                    agg[e]["hosts"].add(r["host"])
                for u, srcs in r["users"].items():
                    users.setdefault(u, set()).update(srcs)
                    if r["user_display"].get(u):
                        report.data["gravatar"].setdefault(u, {})
                        report.data["gravatar"][u].setdefault("display", r["user_display"][u])
                report.data["exposures"].extend(dict(x, host=r["host"]) for x in r["exposures"])
                report.data["secrets"].extend(dict(s, host=r["host"]) for s in r["secrets"])
                for k, vals in r["geo"].items():
                    report.data["geo"].setdefault(k, [])
                    for v in vals:
                        if v not in report.data["geo"][k]:
                            report.data["geo"][k].append(v)
                for u, v in r["gravatar"].items():
                    report.data["gravatar"].setdefault(u, {}).update(v)
                report.data["commits"].extend(r["commits"])
                for ip in r["internal_ips"]:
                    if ip not in report.data["internal_ips"]:
                        report.data["internal_ips"].append(ip)
                if r["git"]:
                    report.data["git"][r["host"]] = r["git"]
                if r["tls_pii"]:
                    report.data["tls_pii"][r["host"]] = r["tls_pii"]
                report.data["harvest"]["metadata"].extend(r["metadata"])
                report.data["harvest"]["ldap"].extend(r["ldap"])
                report.data["harvest"]["vrfy"].extend(r["vrfy"])
                if r["emails"] or r["users"] or r["exposures"]:
                    log("%-50s +%d mail +%d usr +%d exp" % (r["host"], len(r["emails"]),
                                                            len(r["users"]),
                                                            len(r["exposures"])), "OK")

        for e in report.data["harvest"].get("se", []) + report.data["harvest"].get("pgp", []):
            if harvester._scope_ok(e):
                agg.setdefault(e, {"sources": {"search/pgp"}, "hosts": {"external"}})

        for e in sorted(agg):
            dom = e.rpartition("@")[2]
            gov = is_gov_email(e)
            if not gov and not args.include_non_gov:
                continue
            report.data["harvest"]["emails"].append({
                "email": e, "domain": dom, "gov": gov,
                "sector": sector_of(dom.split(".")[0], e.rpartition("@")[0].split(".")[0]),
                "sources": sorted(agg[e]["sources"]), "host": sorted(agg[e]["hosts"])[0]})

        bd = defaultdict(int)
        for row in report.data["harvest"]["emails"]:
            bd[row["domain"]] += 1
        report.data["harvest"]["domain_breakdown"] = dict(sorted(bd.items(), key=lambda x: -x[1]))
        sec = defaultdict(int)
        for row in report.data["harvest"]["emails"]:
            if row["sector"]:
                sec[row["sector"]] += 1
        report.data["harvest"]["sectors"] = dict(sorted(sec.items(), key=lambda x: -x[1]))
        report.data["harvest"]["gov_emails"] = [r for r in report.data["harvest"]["emails"] if r["gov"]]
        report.data["harvest"]["users"] = [{"user": u, "sources": sorted(s)}
                                           for u, s in sorted(users.items())]

        known = [d for d in bd if is_gov_email("x@" + d)] or apexes
        cands = set()
        for u in list(users)[:1000]:
            for local in local_candidates(u, report.data["gravatar"].get(u, {}).get("display", "")):
                for dom in known[:10]:
                    cands.add("%s@%s" % (local, dom))
        have = {r["email"] for r in report.data["harvest"]["emails"]}
        report.data["harvest"]["candidates"] = sorted(cands - have)[:20000]

        if args.role_probe and mx_hosts:
            probes = ["%s@%s" % (r, a) for a in apexes[:4] for r in ROLE_MAILBOXES]

            def rp(addr):
                code, _ = smtp_verify(mx_hosts[0], "postmaster@%s" % apexes[0], addr,
                                      timeout=args.smtp_timeout)
                return addr, code

            with cf.ThreadPoolExecutor(max_workers=12) as ex:
                for addr, code in ex.map(rp, probes):
                    if code in (250, 251):
                        report.data["harvest"]["role_probes"].append({"email": addr, "code": code})
                        report.data["harvest"]["emails"].append({
                            "email": addr, "domain": addr.rpartition("@")[2], "gov": True,
                            "sector": sector_of(addr.rpartition("@")[0]),
                            "sources": ["smtp-role-probe"], "host": apexes[0]})
                        log("role confirmed: %s" % addr, "OK")

        if args.verify_emails and mx_hosts:
            tv = [r["email"] for r in report.data["harvest"]["emails"]]
            report.data["harvest"]["verification"] = harvester.verify(tv)

    report.finalise()
    if args.json:
        report.write(args.json)
        log("JSON → %s" % args.json, "OK")
    if args.emails_out:
        report.write_emails(args.emails_out)
        log("emails → %s.{json,csv}" % args.emails_out, "OK")
    if args.markdown:
        os.makedirs(os.path.dirname(os.path.abspath(args.markdown)), exist_ok=True)
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(report.markdown())
        log("markdown → %s" % args.markdown, "OK")
    if args.stdout:
        print(json.dumps(report.data, indent=2, default=str))

    s = report.data["stats"]
    print()
    log("DONE — apexes=%d subs=%d live=%d mail=%d gov=%d users=%d grav=%d/%d ldap=%d exp=%d crit=%d"
        % (s["apexes"], s["subdomains_found"], s["hosts_live"], s["harvested_emails"],
           s["gov_emails"], s["harvested_users"], s["gravatar_hashes"],
           s["gravatar_confirmed"], s["ldap_hits"], s["exposures"], s["critical"]), "OK")
    return 0

def build_parser():
    p = argparse.ArgumentParser(
        prog="venice-recon",
        description="Global government recon: subdomains, exposures, secrets, users, emails.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python venice-recon.py gob.cu -A -o cu.json --emails-out cu_emails
  python venice-recon.py --country cu,ec,br -A -o latam.json
  python venice-recon.py gob.cu sld.cu uh.cu -A -o cuba.json
""")
    p.add_argument("targets", nargs="*")
    p.add_argument("-T", "--targets-file", default=None)
    p.add_argument("-C", "--country", default=None,
                   help="comma separated ISO codes -> gov apexes (cu,ec,br)")
    p.add_argument("--gov-world", action="store_true",
                   help="every government TLD worldwide in scope")
    p.add_argument("-A", "--aggressive", action="store_true")
    p.add_argument("-o", "--json", default=None)
    p.add_argument("--emails-out", default=None)
    p.add_argument("--markdown", default=None)
    p.add_argument("--stdout", action="store_true")
    p.add_argument("--apex", default=None)
    p.add_argument("--scope", default=None)
    p.add_argument("--threads", type=int, default=40)
    p.add_argument("--port-threads", type=int, default=12)
    p.add_argument("--rps", type=float, default=60.0)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--smtp-timeout", type=float, default=10.0)
    p.add_argument("--max-hosts", type=int, default=0)
    p.add_argument("--resolvers", default=None)
    p.add_argument("--proxy", default=None)
    p.add_argument("--wordlist", default=None)
    p.add_argument("--ports", default=None)
    p.add_argument("--deep", action="store_true")
    p.add_argument("--permute", action="store_true")
    p.add_argument("--permute-seed", type=int, default=60)
    p.add_argument("--permute-max", type=int, default=4000)
    p.add_argument("--zone-transfer", action="store_true")
    p.add_argument("--chaos-key", default=os.environ.get("CHAOS_KEY"))
    p.add_argument("--skip-sources", nargs="*", default=[])
    p.add_argument("--no-passive", action="store_true")
    p.add_argument("--no-brute", action="store_true")
    p.add_argument("--no-ports", action="store_true")

    h = p.add_argument_group("harvest & exposure")
    h.add_argument("--no-harvest", dest="harvest", action="store_false")
    h.add_argument("--harvest-hosts", type=int, default=0)
    h.add_argument("--harvest-max-pages", type=int, default=25)
    h.add_argument("--harvest-max-docs", type=int, default=15)
    h.add_argument("--secrets", action="store_true")
    h.add_argument("--gravatar", action="store_true")
    h.add_argument("--gravatar-max", type=int, default=800)
    h.add_argument("--geo", action="store_true")
    h.add_argument("--se", action="store_true")
    h.add_argument("--cc", action="store_true")
    h.add_argument("--wp-users", action="store_true")
    h.add_argument("--wp-search", action="store_true")
    h.add_argument("--wp-pages", type=int, default=10)
    h.add_argument("--wp-authors", type=int, default=10)
    h.add_argument("--wp-login-probe", action="store_true")
    h.add_argument("--wp-login-max", type=int, default=60)
    h.add_argument("--xmlrpc", action="store_true")
    h.add_argument("--xmlrpc-max", type=int, default=40)
    h.add_argument("--drupal-users", action="store_true")
    h.add_argument("--joomla", action="store_true")
    h.add_argument("--api-users", action="store_true")
    h.add_argument("--graphql", action="store_true")
    h.add_argument("--ldap", action="store_true")
    h.add_argument("--vrfy", action="store_true")
    h.add_argument("--vrfy-max", type=int, default=80)
    h.add_argument("--autodiscover", action="store_true")
    h.add_argument("--saml-meta", action="store_true")
    h.add_argument("--rdap", action="store_true")
    h.add_argument("--role-probe", action="store_true")
    h.add_argument("--verify-emails", action="store_true")
    h.add_argument("--verify-max", type=int, default=300)
    h.add_argument("--auto-suffix", action="store_true")
    h.add_argument("--allow-free-mail", action="store_true")
    h.add_argument("--include-non-gov", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-V", "--version", action="version", version="venice-recon " + VERSION)
    return p

def main():
    args = build_parser().parse_args()
    if not args.json and not args.stdout and not args.markdown:
        base = slug(split_domain((args.targets or ["target"])[0])[0])
        args.json = "recon_%s_%s.json" % (base, datetime.now().strftime("%Y%m%d_%H%M%S"))
    try:
        sys.exit(run(args))
    except KeyboardInterrupt:
        log("interrupted", "ERR")
        sys.exit(130)

if __name__ == "__main__":
    main()