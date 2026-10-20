# rectool

API-less OSINT reconnaissance in Go. Give it any combination of full name, username, email, phone, domain, IP address, company and location; it decides which modules apply, runs them concurrently on a shared worker pool, follows the strongest new leads it discovers, and exports JSON / CSV / TXT reports.

> Use only on subjects you are lawfully permitted to investigate. Results are leads, not proof of identity.

## Install (Linux)

rectool targets Linux (Debian/Ubuntu/Kali, Fedora/RHEL, Arch, openSUSE, Alpine; amd64 and arm64). Copy this directory to the machine and run the installer:

```bash
chmod +x install.sh
./install.sh            # system-wide: /usr/local/bin/rectool (uses sudo)
./install.sh --user     # no root: ~/.local/bin/rectool
./update.sh             # later: pull the latest version, rebuild, reinstall (--check only looks)
```

The installer installs the OS packages it needs, installs Go 1.22+ if missing (checksum-verified from go.dev), builds a static binary, downloads the 600+ site WhatsMyName list into `share/rectool/` (rectool finds it automatically), and installs the optional tools `whois`, `dig`, `sherlock` and `theHarvester` on a best-effort basis. Options: `--no-deps`, `--no-extras`, `--no-sites`, `--prefix DIR`, `--uninstall`.

If `~/.local/bin` is not in your `PATH` after a `--user` install, the script prints the line to add.

Manual build instead (needs Go 1.22+):

```bash
make build              # bin/rectool
make linux-arm64        # cross-compile, e.g. for a Raspberry Pi
```

## Usage

```bash
rectool -u johndoe -verify -o reports
rectool -n "Jane Doe" -e jane@example.com -p +15551234567 -derive -o reports
rectool -d example.com -c "Example Inc" -l "Cairo, Egypt" -o reports
rectool -ip 203.0.113.10
rectool                 # on a terminal with no flags: interactive prompts
rectool -list-modules
rectool -version
```

### Web UI

```bash
rectool -web 127.0.0.1:8080
```

It prints a URL containing a random access token; open it in your browser (the token is exchanged once for an HttpOnly, SameSite=Strict cookie).

**Case panel (left).** Fill in whatever you know: every input, collector and option has an **ⓘ** hint (English and Arabic) explaining what turning it on will do. *Aggressive* is on by default; untick it for a quicker, lighter run. Proxies are optional.

**Workspace (right).** Live progress per collector, then seven views of the same data:

| View | What it gives you |
|---|---|
| **Identity** | Who the findings add up to: the best-matching person as a dossier with confirmation badges, other candidates kept apart, "search again with these details" |
| **Overview** | KPI tiles, key facts about the subject (names, handles, e-mails, phones, domains, IPs, places), notable risk signals (expired TLS, spoofable mail, takeover candidates, stealer-log exposure…), a reliability distribution, findings per collector |
| **Intelligence tree** | Everything organised as Subject → Identity / Contact points / Online accounts / Infrastructure / Organisation / Exposure / Crypto / Search leads, searchable, click any leaf for its evidence |
| **Relationship graph** | Force-directed map of how leads were found: subject → inputs → what the first pass found → what following those leads found. Drag, zoom, click nodes, hide weak leads |
| **Findings** | Filterable table (collector, category, minimum confidence); click a row for the full record |
| **Photos** | Gallery of every profile picture found, with "same picture" groups, size/hash, and reverse-image-search links |
| **Coverage & integrity** | Per-collector results, **every check that could not complete** (a coverage gap is not proof of absence), run settings, and a SHA-256 digest of the evidence |

History is kept in memory (last 50 cases); add `-o DIR` to also save every finished report. Exports (JSON / CSV / TXT) include entities, gaps, settings and the integrity digest.

- Binds to loopback by default. On a headless server, use an SSH tunnel: `ssh -L 8080:127.0.0.1:8080 user@server`, then open the printed URL locally.
- Binding to a non-loopback address (e.g. `0.0.0.0:8080`) works but is plain HTTP; put it behind a TLS reverse proxy and keep the token secret. Use `-web-token` to set your own token (16+ characters).
- Protections: required token, Host-header check (anti DNS-rebinding), same-origin + custom-header check on POST (anti CSRF), strict Content-Security-Policy, no external assets, all scraped text rendered as text (no HTML injection).
- The UI exposes only a safe subset of options. Site-list paths, external tools and tools files stay under command-line control (`-sites`, `-tools`, `-tools-file`); `-workers`, `-timeout`, `-proxy` etc. set the defaults for UI scans. `-web-max-scans` limits concurrent scans (default 2).

### Reliability

- **Coverage gaps are first-class.** Blocked, timed-out and offline checks are recorded per collector and shown in the UI and the TXT/JSON reports.
- **Retry pass.** Username probes that fail at connection level (timeouts, DNS) are retried once, gently, before being reported, so a congested link does not silently lose coverage. `-inflight N` caps simultaneous requests (default 110; lower it on weak networks).
- **Site self-test.** `rectool -selftest-sites` checks every platform against its known account and a random one, then disables the ones with stale signatures or that report everything as existing (sites merely blocked from your network stay enabled). The list is stored in `$RECTOOL_DATA` / `~/.local/share/rectool/sites-disabled.json`; `-all-sites` ignores it, deleting the file resets it. Run it occasionally: platforms change.
- **Attribution scoring** keeps unrelated people who share a handle out of the leads that get followed.
- **Integrity digest** (SHA-256 of target, entities and findings) and recorded run settings make a report verifiable and reproducible.

### CLI

At least one identifier is required. Ctrl-C stops the run and still writes a partial report (exit code 130).

## Inputs

All optional; each one you add unlocks more sources:

| Input | Flag | Unlocks |
|---|---|---|
| Full name | `-n` | search dorks, Wikidata / ORCID / OpenAlex / GitHub name search |
| Username | `-u` | 500+ site probe, deep profile data (GitHub, Keybase, npm, GitLab, Mastodon, …) |
| Email | `-e` | MX/provider, Gravatar profile, stealer-log exposure, verified web mentions; its domain is investigated too |
| Phone | `-p` | offline analysis, verified web mentions |
| Domain / URL | `-d` | DNS, e-mail security, RDAP, subdomains, website, TLS, archive, exposure |
| IP address | `-ip` | rDNS, ASN, RDAP, geolocation, open ports/CVEs (passive), co-hosted domains, TLS banner |
| Company | `-c` | likely websites (verified), Wikipedia/Wikidata, GitHub org, company dorks |
| Nickname / alias | `-a` | handle variants (`dark.knight`, `darkknight`, …) probed on every platform, plus alias dorks |
| ASN | `-asn` | owner, announced prefixes, BGP neighbours, registration contacts |
| Crypto wallet | `-w` | Bitcoin / Ethereum balance, activity window, ENS name, scam-report dorks |
| Location | `-l` | refines name/company searches (not an identifier on its own) |

A pasted **profile link** in the domain field (`-d https://x.com/handle`) is recognised and treated as a username, not a domain. A phone number without `+` is parsed using the country in `-l`.

**One clue is enough.** Give only a phone number, a nickname, a wallet or a profile link and every module that can use it runs; whatever it finds (emails, domains, IPs, usernames) is followed automatically. Use `-aggressive` (a checkbox, on by default, in the web UI) for maximum coverage: derived usernames, verified hits, pivot depth 3 and up to 25 followed leads, 120 dorks.

## Modules

| Module | Needs | What it does |
|---|---|---|
| `social` | username / alias | Probes **692 platforms** (the WhatsMyName list, embedded; adult sites opt-in with `-categories nsfw`) by status code and page content; adds page title/bio/avatar when present. |
| `phone` | phone | libphonenumber analysis: validity, country, region/area, line type (mobile / landline / VoIP), original carrier, time zones, all formats. |
| `crypto` | wallet | Bitcoin (mempool.space) and Ethereum/EVM (Blockscout): balance, tx counts, activity window, contract status, ENS name. |
| `asn` | ASN | RIPEstat + RDAP: holder, announced prefixes, BGP neighbours, contacts. |
| `profiles` | username | Real profile data from GitHub (profile, SSH keys, **commit e-mails**), Keybase (verified accounts), GitLab, npm (maintainer e-mail), Hacker News, DEV, Docker Hub, Mastodon, Stack Overflow, Lichess, Chess.com, Reddit. |
| `domain` | domain | DNS records; SPF/DMARC/DKIM and mail provider; SaaS used (TXT tokens); RDAP registration and contacts; **subdomains** (crt.sh, certspotter, HackerTarget, TLS SANs) resolved and checked for wildcard DNS; website title/tech/security headers/cookies/tracking IDs; emails, phones and social links on the site; robots.txt, sitemap, security.txt; TLS certificate; Internet Archive URLs; stealer-log exposure counts. |
| `ip` | IP | Reverse DNS, ASN (Team Cymru via DNS), RDAP, geolocation, ports/CVEs already indexed by Shodan InternetDB (no scanning by rectool), co-hosted domains, TLS certificate and web banner. |
| `company` | company | Candidate domains (verified against the live page; only the best one is followed), Wikipedia, Wikidata, GitHub organisation. |
| `images` | name or username | Pictures of the subject: avatars of the handle on ~18 services (via unavatar.io) and web image search for the quoted name, filtered to pages whose title has the name. Always shown as unverified candidates, separate from profile photos. |
| `people` | full name, LinkedIn link or pasted text | Candidate profiles as structured records for identity resolution: LinkedIn public view (when allowed), ORCID, Wikidata, OpenAlex, Crossref authors, Wikipedia, GitHub, Fediverse WebFinger, Wayback snapshots of profile links, CV documents, pasted text. Names match across spellings and scripts (Mohamed / Muhammad / محمد, Bob / Robert). |
| `footprint` | email or phone | MX, Gravatar profile (name, linked accounts, sites), infostealer exposure (counts/dates only), phone analysis, and web mentions that are verified by fetching each page. |
| `dorks` | any identifier | Generates dorks from every identifier (site:, filetype:, inurl:, leaks, code, people…) and scrapes Brave / Bing / DuckDuckGo / Google. |
| `syswrap` | domain, username | Runs `whois`, `dig`, `theHarvester`, `subfinder`, `whatweb`, `sherlock`, `maigret`, `holehe`, `phoneinfoga` and your custom tools through `os/exec` (those installed). |

Select modules with `-modules domain,ip`. Modules whose required input is missing are skipped and listed in the summary.

### Photos

Profile pictures from ~22 sources (and Gravatar by e-mail) are downloaded by rectool, fingerprinted (SHA-256 + perceptual hash) and compared. The same picture on different sites is reported as a finding and highlighted in the **Photos** tab, with reverse-image-search links (Google Lens, Yandex, TinEye, Bing) per picture. Downloads go through an SSRF-guarded fetcher; the web UI shows them through an authenticated proxy so your browser never contacts third-party hosts. No face recognition is performed.

### What is covered, and what is not

See [docs/COVERAGE.md](docs/COVERAGE.md) for the per-identifier map of sources and limits. Anything that needs a login, CAPTCHA or payment is not automated; the report lists those sources as **manual leads** with pre-filled links.

### Identity resolution: different people stay different

A name or a handle is not an identity. Every profile-like finding (GitHub, Keybase, ORCID, Wikidata, OpenAlex, LinkedIn's public view, personal sites, CVs, Gravatar, …) becomes a **record**, and records are clustered into **identities** only on evidence:

- a shared e-mail, phone, unique ID (ORCID, Wikidata…), linked account or website, or the same profile picture;
- or the same name plus at least two independent matching attributes (place, employer, school, e-mail domain, the same handle on another platform).

Two different accounts on the same platform are never merged by soft evidence (impersonators copy names, places and employers); copies and duplicates are demoted. Each identity is **scored against what you supplied** (name, e-mail, phone, username, domain, company, location, pasted profile link), contradictions lower the score, and every attribute is labelled: ✔ *confirmed* (two or more independent platforms), *self-reported* (the person's own profile) or *1 source*. The **Identity** tab shows the best match as a dossier (photo, role, employers, education, interests, e-mail, accounts, websites, CV), the other candidates separately, and a banner when several people plausibly match, with a button to search again using a candidate's details. Only the best-matching identity's e-mails, accounts and websites are followed automatically; when it is ambiguous, none is.

Sources for a name: ORCID (employments, education, keywords, links), Wikidata (occupation, employer, education, cross-platform IDs, photo), OpenAlex (institutions, research topics), GitHub profiles, personal sites (schema.org Person data) and CV/resume PDFs. A CV is accepted only if its *header* carries the person's name (a CV that merely mentions the name is rejected) and is checked against your e-mail, phone, employer, location and handle.

**LinkedIn.** LinkedIn actively blocks automated access (HTTP 999). rectool can read the logged-out public view of a specific profile URL when LinkedIn allows it, slowly and without evading anything, and stops at the first refusal. When LinkedIn refuses, use the manual link, or open the profile yourself and paste its text (or a "Save to PDF" export) into the **Paste text** box (CLI: `-notes-file`); it is parsed into a record and takes part in identity matching. LinkedIn's terms restrict automated access; use this only where you are entitled to.

**`-browser` (opt-in).** If plain HTTP is refused, rectool can open the same logged-out public page with the Chrome / Chromium / Edge installed on your machine (headless, default settings, empty profile; set `RECTOOL_BROWSER` to pick one). It uses no stealth flags, no cookies and no login, and stops at a sign-in wall or CAPTCHA. Whether LinkedIn serves the page depends on your IP and its current rules; in our own test from a home connection it showed the sign-in wall, so treat this as best effort. The public view contains name, headline, location, roles, schools, about and photo; it never contains e-mail or CV, which LinkedIn shows only to logged-in connections. For those, paste your own logged-in view into the Notes box.

## Report formats

`-formats json,csv,txt,html,graphml,stix,entities` (web UI: export buttons). `html` is a single self-contained file with the identity dossier and embedded photos; open it and print to PDF. `graphml` opens in Gephi, yEd and Maltego; `stix` is a STIX 2.1 bundle; `entities` is a CSV of every discovered entity.

### Pivoting: findings feed each other

Modules report **entities** (emails, domains, IPs, usernames, names, phones) they discover. After the first pass the engine follows the *strong* ones once (up to `-max-pivots`, default 10): a found email goes to `footprint`, a domain to `domain`, an IP to `ip`, a username to `social` + `profiles`. Results of that second pass are tagged `via email:…` etc. Disable with `-no-pivot`; `-modules` restrictions also apply to the second pass.

### Attribution: a username is not an identity

`torvalds` on npm or Docker Hub is usually someone else. The `profiles` module therefore scores every profile before anything is followed: against the identifiers you supplied (name, email, domain, company, location), against profiles on other platforms (shared name / website / location), and for internal consistency (a commit e-mail that matches the handle). Profiles that don't reach the threshold are reported as **unverified, 40% confidence** and their leads are *not* followed. Supplying more identifiers (even just a full name) raises confidence for genuine matches.

### Data sources and what "API-less" means here

No API keys or accounts are used anywhere. Besides scraping and DNS, the tool reads a handful of **public, unauthenticated web endpoints** that sites serve to anyone: RDAP, crt.sh / certspotter / HackerTarget (subdomains, reverse IP), Internet Archive CDX, Gravatar, GitHub / GitLab / Keybase / npm / Hacker News / Mastodon / Lichess / Chess.com / DEV / Docker Hub / Stack Exchange public profile data, Wikipedia / Wikidata / ORCID / OpenAlex, Shodan InternetDB, ipwho.is, Team Cymru (DNS) and Hudson Rock's free stealer-index counts. Several are rate-limited per IP or go offline at times; failures are reported as errors and never stop a run.

### More social sites

The binary embeds a small seed list (about 84 sites). `install.sh` downloads the community [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) list (600+ sites) to `/usr/local/share/rectool/wmn-data.json` (or `~/.local/share/rectool/` for `--user`), and rectool uses it automatically. Lookup order: `-sites`, `$RECTOOL_DATA`, `$XDG_DATA_HOME/rectool`, `~/.local/share/rectool`, `/usr/local/share/rectool`, `/usr/share/rectool`, then the embedded list. To refresh it: `sh scripts/update-sites.sh /usr/local/share/rectool/wmn-data.json`.

Site signatures drift as platforms change. Use `-verify` and treat results as leads.

### Custom syswrap tools

`-tools-file` takes a JSON array (see `configs/tools.example.json`):

```json
[{
  "name": "holehe", "binary": "holehe",
  "args": ["--only-used", "{email}"],
  "pattern": "^\\[\\+\\]\\s+(?P<title>\\S+)",
  "category": "email", "timeout_sec": 90
}]
```

`{username}`, `{email}`, `{domain}` and `{phone}` are substituted into args and also decide when the tool runs. `pattern` is matched per output line; the named groups `title` and `url` feed the finding and any other named group goes into its details. Commands run directly, never through a shell, and inputs that don't pass validation (leading `-`, spaces, shell characters) are dropped.

## Architecture

```
cmd/rectool/            CLI: flags, wiring, signal handling, export
internal/
  models/               Target, Finding, Report (shared data types)
  scanner/              Scanner interface + Deps handed to every module
  app/                  Builds a configured engine from one Options value (CLI and web share it)
  web/                  Web UI: JSON API, SSE live results, auth middleware, embedded static/ front end
  engine/               Planner (Enrich/Plan) and Run: dispatch, collect, report
  pool/                 Bounded worker pool shared by all modules
  httpx/                HTTP client: UA rotation, header spoofing, proxies, retry
  output/               Coloured console, JSON / CSV / TXT export
  modules/
    social/             Username enumeration (+ embedded sites_default.json)
    profiles/           Deep profile data + attribution scoring
    domain/             DNS, RDAP, subdomains, website, TLS, archive, exposure
    ip/                 rDNS, ASN, RDAP, geo, passive ports/CVEs, banner
    company/ people/    Organisation and name look-ups
    dorks/              Dork generation, search-engine scrapers, shared Searcher
    footprint/          Email / phone footprint
    syswrap/            External CLI tool wrappers
  extract/ probe/ rdap/ intel/   Shared helpers: HTML extraction, web/TLS probes, RDAP client, normalisation
configs/  data/  scripts/
```

**Run flow**

1. `engine.Enrich` validates and normalises inputs and derives alias usernames (email local part; name permutations with `-derive`).
2. `engine.Plan` asks each registered module `CanRun(target)` and honours `-modules`.
3. `engine.Run` starts the selected modules concurrently. They push work onto one shared `pool.Pool`, so total in-flight tasks stay at `-workers` however many modules run.
4. Modules call `emit(Finding)`. One collector goroutine counts and stores them, and streams positive hits to the console.
5. The report is sorted (found first), summarised and exported.

**Concurrency rules for modules.** A module's `Scan` runs on its own goroutine, not on a pool worker, so it may submit tasks to `d.Pool` and `wg.Wait()` for them without deadlocking. Tasks must not submit further tasks to the pool. Tasks must honour `ctx`, and `emit` is safe for concurrent use.

**Stealth and evasion.** Each request gets a rotated browser User-Agent, a navigation header set and a random Accept-Language. There is retry with jittered backoff and optional proxy rotation. TLS and HTTP/2 fingerprints are Go's own. Search engines that serve a bot challenge are disabled for the rest of the run; challenges are never solved or bypassed.

## Adding a module

1. Create `internal/modules/<name>/` with a type implementing `scanner.Scanner`:

   ```go
   type Scanner interface {
       Name() string
       Description() string
       CanRun(t models.Target) bool
       Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error
   }
   ```

2. In `Scan`, fan out with `d.Pool.Submit(ctx, fn)`, use `d.HTTP.Do(...)` for requests, call `d.Progress` if you want a progress bar, and emit `models.Finding` values. Use `StatusFound` / `StatusUncertain` for leads, `StatusNotFound` for negatives and `StatusError` for failures. Set `Confidence` honestly (a search hit is about 0.4, a verified match about 0.9).
3. Register it in `internal/app/app.go` (`Build`): `eng.Register(mymod)`. Both the CLI and the web UI pick it up; the engine needs no changes.
4. Add table-driven tests for any parsing. The existing modules test their parsers and matchers offline.

To share rate-limited resources between modules, pass one instance to both. `dorks.Searcher` is shared by `dorks` and `footprint` this way.

## Development

```bash
go vet ./... && go test -race ./...
```

## Limitations

- **Search engines.** Google and DuckDuckGo usually challenge plain-HTTP scrapers, and Bing may return unrelated pages; Brave works best. Blocked engines are skipped for the rest of the run. The dorks module reports this as errors, and footprint only keeps pages it could fetch and verify. A proxy via `-proxy` may help, but results are never guaranteed.
- **Site signatures.** Social checks depend on each platform's current responses and can produce false positives or negatives.
- **No breach data.** `footprint` does not query or download breach or credential databases.
- **Offline phone analysis.** The calling-code table is partial and does not look up carriers or owners.

## Credits

The username site list is [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) (CC BY-SA 4.0), see [NOTICE.md](NOTICE.md). Phone metadata comes from Google's libphonenumber via [nyaruka/phonenumbers](https://github.com/nyaruka/phonenumbers).
