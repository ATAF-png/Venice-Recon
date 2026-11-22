<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/ff82fdaa-dbef-4507-b0bd-4b54533a0e0e" />







# Venice-Recon
Aggressive multi-target reconnaissance for government domains worldwide — subdomains, secrets, exposed configs, users and emails, to JSON.


Aggressive, single-file reconnaissance harness for government and public-sector domains worldwide.

Point it at one domain or a whole country. It enumerates subdomains, fingerprints
infrastructure, hunts exposed configuration and credentials, enumerates users across
seventy-odd endpoint families, and harvests email addresses — then writes everything to
severity-scored JSON.

Built for the boring reality of public-sector estates: WordPress installs that were
never hardened, Drupal nodes running autocomplete, open LDAP directories, Zimbra boxes
with SOAP exposed, and `.env` files that got committed.

---

## Disclaimer

Recon here is **active**. It sends real requests, attempts anonymous LDAP binds, SMTP
`VRFY`/`EXPN`, and XML-RPC calls. Almost all of it is unauthenticated and low-impact, but
it is not passive.

Use it against anything you like. For engagements, get authorisation first. For
government estates, the general expectation is that public-facing reconnaissance is
fine — but confirm before running the intrusive layers (`--ldap`, `--vrfy`,
`--wp-login-probe`, `--xmlrpc`) against a target you care about.

No exploits are run. Nothing is written to the target.

---

## Features

**Subdomain enumeration**
- 12 passive sources: crt.sh, certspotter, urlscan, OTX, Wayback, RapidDNS, Anubis,
  mnemonic, subdomain.center, bufferover, threatminer, hackertarget
- Common Crawl index mining
- Dictionary brute force with permutation engine
- Wildcard DNS detection and filtering
- Zone transfer (AXFR) attempts
- Multi-label public suffix parsing (`gob.cu`, `co.uk`, `com.br`, `gob.ec`, `admin.ch`)

**Fingerprinting**
- Tech stack: 120+ header, cookie, body and meta signatures
- WAF/firewall: Cloudflare, Akamai, Imperva, F5, Sucuri, ModSecurity, Wordfence,
  Barracuda, FortiWeb, NetScaler, Wallarm, Radware, Azure Front Door
- Auth surface: OIDC, SAML, Shibboleth, CAS, ADFS, Keycloak, Okta, Auth0, Entra ID, LDAP, MFA
- High-value services: Kibana, Portainer, Trino/Presto, Elasticsearch, Jenkins, GitLab,
  Tomcat Manager, MinIO, phpMyAdmin
- Subdomain takeover fingerprints
- TLS certificate subject/issuer/SAN with PII extraction

**Exposure scanning**
- 120 sensitive paths: `.env` variants, `.git/`, `.svn/`, config backups, SQL dumps,
  archives, `phpinfo.php`, `server-status`, `actuator/env`, Telescope, debug logs
- 22 secret patterns: AWS, Google, Stripe, SendGrid, Twilio, Slack, GitHub, GitLab,
  JWTs, private keys, Laravel `APP_KEY`, bcrypt hashes, DB URLs, DB passwords, API tokens
- Severity scoring, `critical` first
- **Soft-404 calibration** so hits aren't drowned in false positives
- Internal IP harvesting

**User enumeration**
- WordPress: REST API with pagination, `avatar_urls` MD5 extraction, alphabetical
  `search=` sweep, author archive brute force, `wp-sitemap-users`, BuddyPress, bbPress,
  RSS `dc:creator`, login oracle, `/wp-json/` route dumping
- Drupal: `/user/autocomplete`, JSON:API, user ID enumeration
- Joomla: `com_contact`, `com_users`
- XML-RPC `wp.getUsersBlogs` oracle
- GraphQL introspection
- 50+ panel and CMS APIs: DMOJ, Discourse, Directus, Strapi, Moodle, Chamilo, GLPI,
  osTicket, Odoo, SuiteCRM, EspoCRM, Mattermost, Rocket.Chat, MinIO, RabbitMQ, Airflow,
  Superset, Metabase, Keycloak, Nextcloud, Nexus, Sonar, GitLab, Gitea, Jenkins, Jira,
  Elasticsearch, Portainer, Consul, Kubernetes, Docker Registry
- **Anonymous LDAP bind** on 389
- **SMTP `VRFY` / `EXPN`**
- **Exchange Autodiscover**
- **SAML / Shibboleth / ADFS federation metadata** contact blocks
- Office and PDF document metadata (`dc:creator`, `/Author`)

**Email harvesting**
- Cloudflare `data-cfemail` XOR decoding
- JS `String.fromCharCode` decoding
- `[at]` / `(at)` / `{at}` / `[dot]` text obfuscation
- `mailto:` parsing, `security.txt`, `humans.txt`, `robots.txt`, sitemaps
- 50 contact, directory and transparency page paths (EN/ES/FR/PT)
- Recursive link following
- **PGP keyserver by-domain lookup** (`keys.openpgp.org`, Ubuntu keyserver)
- Search engine scraping: DuckDuckGo, Bing, Mojeek, Brave, DDG Lite
- RDAP registrant records
- Document mining: PDF, DOCX, XLSX, PPTX, ODT, CSV
- **Gravatar confirmation** — converts a username into a verified address, plus its
  MD5/SHA256 pair, without touching SMTP
- SMTP `RCPT TO` verification with catch-all detection
- 90 role mailbox probes (`prensa`, `compras`, `denuncias`, `rrhh`, `fiscalia`…)
- Local-part pattern inference and fan-out
- Numeric sequence expansion (`compras.farmacosg1` → `…g34`)
- Government classification with sector tagging

**Reporting**
- Severity-ordered JSON
- Email CSV with SMTP result columns
- Gravatar CSV for offline cracking
- Username list
- Markdown summary

---

## Install

Requires Python 3.10+.

```bash
git clone https://github.com//venice-recon.git
cd venice-recon
python3 -m venv .venv
source .venv/bin/activate
pip install requests dnspython mmh3 pypdf
```

Windows:

```bat
py -m venv .venv
.venv\Scripts\activate
pip install requests dnspython mmh3 pypdf
```

`dnspython` enables DNS record types and AXFR. `mmh3` adds Shodan-compatible favicon
hashes. `pypdf` improves PDF text extraction — without it, PDFs are read as raw bytes.

Optional: set `CHAOS_KEY` for the ProjectDiscovery Chaos dataset.

---

## Quick start

```bash
# one domain, everything on
python venice-recon.py gob.cu -A -o cu.json --emails-out cu_emails

# a whole country by ISO code
python venice-recon.py --country cu,ec,bo -A -o latam.json --emails-out latam_emails

# named targets
python venice-recon.py gob.cu sld.cu uh.cu -A -o cuba.json

# from a file
python venice-recon.py -T targets.txt -A -o all.json
```

`-A` enables every layer and raises the limits: 120 threads, 200 rps, 250 pages and
100 documents per host, 800 author IDs, 6000 Gravatar checks.

A first pass on a large space should be bounded:

```bash
python venice-recon.py gob.cu -A --harvest-hosts 200 --no-ports -o cu.json --emails-out cu_emails
```

---

## Usage notes

### Scope

Given `gob.cu`, the tool automatically puts the whole country in scope: `.cu`,
`.gob.cu`, `.edu.cu`, `.mil.bo`, `.inf.cu`, `.co.cu`, `.tur.cu` and every other
second-level label. Sibling state entities and universities are included without
extra flags.

`--gov-world` widens this to every government SLD on earth. `--scope` adds arbitrary
domains. `--apex` overrides the derived apex.

### Rate

Defaults are 40 threads and 60 rps. `-A` raises both. If you start seeing 429s or
connection resets, pull back:

```bash
python venice-recon.py gob.cu -A --threads 30 --rps 25
```

Use `--resolvers 1.1.1.1,9.9.9.9` to avoid hammering your ISP resolver.

### Port 25

`--vrfy`, `--role-probe` and `--verify-emails` need outbound port 25. Most consumer
ISPs block it. Check first:

```bash
nc -vz $(dig +short MX example.gov | head -1 | awk '{print $2}') 25
```

If it's blocked, those three layers return nothing while Gravatar and everything else
still works. Run from a VPS to get them.

### Documents

Document mining downloads files. Cap it with `--harvest-max-docs` on big runs. PDF
metadata frequently carries the author's real name.

### LDAP

`--ldap` tries anonymous bind against the host, `ldap.<apex>` and `dc.<apex>`, then
searches `(objectClass=person)` for `mail`, `cn`, `uid`. Open directories are the
single highest-yield vector when present — and usually dwarf everything else in a run.

---

## Flags

### Targets

| Flag | Description |
|---|---|
| `targets` | One or more domains or URLs |
| `-T, --targets-file` | File of domains, one per line, `#` comments |
| `-C, --country` | Comma-separated ISO codes, expands to that country's gov SLD |
| `--gov-world` | Every government TLD worldwide in scope |
| `--apex` | Force the enumeration apex |
| `--scope` | Extra in-scope domains, comma separated |

### Output

| Flag | Description |
|---|---|
| `-o, --json` | JSON output path |
| `--emails-out` | Base path for `.json`, `.csv`, `_gravatar.csv`, `_users.txt` |
| `--markdown` | Markdown summary path |
| `--stdout` | Also print JSON |

### Performance

| Flag | Default | Description |
|---|---|---|
| `-A, --aggressive` | off | Enable everything, raise limits |
| `--threads` | 40 | Worker threads |
| `--port-threads` | 12 | Host workers for port scans |
| `--rps` | 60 | Global requests per second |
| `--timeout` | 8 | Per-request timeout |
| `--smtp-timeout` | 10 | SMTP timeout |
| `--max-hosts` | 0 | Cap HTTP probing |
| `--harvest-hosts` | 0 | Cap harvested hosts |
| `--harvest-max-pages` | 25 | Pages per host |
| `--harvest-max-docs` | 15 | Documents per host |
| `--permute-seed` | 60 | Permutation seeds |
| `--permute-max` | 4000 | Max permutations |
| `--gravatar-max` | 800 | Gravatar checks |
| `--verify-max` | 300 | SMTP verifications |
| `--vrfy-max` | 80 | VRFY probes |
| `--xmlrpc-max` | 100 | XML-RPC probes |
| `--wp-authors` | 10 | Author IDs to try |
| `--wp-pages` | 10 | REST pages |
| `--wp-login-max` | 60 | Login oracle probes |
| `--drupal-users` | 0 | Drupal user IDs |

### Phases

| Flag | Description |
|---|---|
| `--no-passive` | Skip passive sources |
| `--no-brute` | Skip brute force |
| `--no-ports` | Skip port scan |
| `--no-harvest` | Skip all harvesting |
| `--skip-sources` | Passive sources to skip |
| `--permute` | Enable permutation engine |
| `--zone-transfer` | Attempt AXFR |
| `--ports` | Comma-separated port list |
| `--wordlist` | Extra brute-force wordlist |
| `--resolvers` | Custom DNS resolvers |
| `--proxy` | HTTP(S) proxy |

### Harvest layers

| Flag | Description |
|---|---|
| `--secrets` | Sensitive file and secret scan |
| `--gravatar` | Gravatar email confirmation |
| `--geo` | GPS, address and phone extraction |
| `--se` | Search engine scraping |
| `--cc` | Common Crawl path discovery |
| `--wp-users` | WordPress enumeration |
| `--wp-search` | WordPress alphabetical sweep |
| `--wp-login-probe` | WordPress login oracle |
| `--xmlrpc` | XML-RPC user oracle |
| `--drupal-users` | Drupal enumeration |
| `--joomla` | Joomla contact components |
| `--api-users` | Panel and CMS user APIs |
| `--graphql` | GraphQL introspection |
| `--ldap` | Anonymous LDAP bind |
| `--vrfy` | SMTP VRFY/EXPN |
| `--autodiscover` | Exchange Autodiscover |
| `--saml-meta` | SAML/ADFS metadata contacts |
| `--rdap` | RDAP registrant lookup |
| `--role-probe` | SMTP role mailbox probing |
| `--verify-emails` | SMTP RCPT verification |
| `--auto-suffix` | Whole-country scope |
| `--allow-free-mail` | Keep Gmail/Hotmail found on pages |
| `--include-non-gov` | Keep non-government addresses |

### Misc

| Flag | Description |
|---|---|
| `-q, --quiet` | Suppress info logging |
| `-V, --version` | Print version |
| `--deep` | Probe every service path |

---

## Output

```
{
  "meta":        { tool, version, apexes, started, finished, args },
  "dns":         { apex: { a, mx, ns, txt, soa } },
  "wildcard":    { apex: { detected, ips } },
  "subdomains":  [ ... ],
  "hosts":       { host: { status, title, headers, tech, waf, auth, tls } },
  "exposures":   [ { path, severity, size, secrets, snippet } ],
  "secrets":     [ { type, severity, value, context, source } ],
  "gravatar":    { username: { md5, sha256, email } },
  "geo":         { coords, addresses, places, phones },
  "ports":       { host: [ { port } ] },
  "commits":     [ ... ],
  "internal_ips":[ ... ],
  "git":         { host: { remote } },
  "tls_pii":     { host: { emails, CN, O, OU } },
  "harvest": {
    "emails":       [ { email, domain, gov, sector, sources, host } ],
    "gov_emails":   [ ... ],
    "users":        [ { user, sources } ],
    "domain_breakdown": { domain: count },
    "sectors":      { sector: count },
    "patterns":     { pattern: count },
    "candidates":   [ ... ],
    "role_probes":  [ ... ],
    "ldap":         [ ... ],
    "vrfy":         [ ... ],
    "verification": { email: { code, accepted, catch_all } }
  },
  "stats":       { ... }
}
```

`--emails-out` additionally writes:

- `<base>.csv` — email, domain, gov, sector, sources, host, SMTP result
- `<base>_gravatar.csv` — username, md5, sha256, confirmed email
- `<base>_users.txt` — usernames only

---

## How it works

1. Parse targets, derive apexes, expand scope suffixes
2. Collect DNS baseline, detect wildcards
3. Run passive sources, Common Crawl, search engines, PGP keyservers
4. Brute force and permute
5. Resolve, filter against wildcard IPs
6. Port scan
7. Probe HTTP, fingerprint stack and WAF, record TLS PII
8. Per live host: harvest pages, documents, users, exposures
9. Gravatar-confirm, role-probe, SMTP-verify
10. Score, deduplicate, write

---

## Limits

- **Hunter.io / Snov / Apollo / Clearbit** hold proprietary address indexes. Not
  integrated — they need paid keys, and coverage of `.gob.xx`-class domains is thin.
- **HIBP** needs a key and is per-address, not per-domain.
- **GitHub code search** needs a token; only `/search/users?q=` works unauthenticated.
- **LDAPS on 636** needs a cert and usually credentials.
- **Gravatar** only confirms accounts that registered one. Hashes from `avatar_urls` are
  still captured for offline cracking either way.
- **Port 25** blocking disables VRFY and RCPT verification.

Realistic ceiling on a defended national space with everything enabled is several
hundred to a few thousand addresses and usernames. The volume comes from scope, search
engines, LDAP/VRFY/SAML and pattern fan-out — not from any one trick.

---

## Roadmap

- [ ] Hunter.io / Snov integration via API key
- [ ] HIBP domain breach lookup
- [ ] GitHub token-backed code search
- [ ] Shodan / Censys / FOFA connectors
- [ ] Screenshot capture
- [ ] Resume from state file
- [ ] Nuclei template handoff

---

## Contributing

Issues and PRs welcome. New fingerprint tables, passive sources and enumeration
endpoints are the most useful contributions. Keep it single-file.

---

## License

MIT
