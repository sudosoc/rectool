# What rectool collects — and what it cannot

This is the honest coverage map. "Collected" means the tool does it automatically from public, unauthenticated sources. "Manual" means it needs a login, a CAPTCHA or payment; rectool does not (and will not try to) bypass those, and instead prints a pre-filled link under **Coverage → Manual leads** in the web UI and in the reports.

Nothing here can promise *everything* about a person: private accounts, data behind logins, and information that was never published are out of reach by design. The tool's job is to find everything that is publicly findable without credentials, show its provenance and confidence, and tell you exactly what it could not check.

## Per identifier

| You give | Collected automatically | Main sources | Manual / not possible |
|---|---|---|---|
| **Username** | presence on 630+ platforms; profile data (real name, location, bio, company, websites, linked accounts, public e-mails, commit e-mails, SSH-key presence) from ~22 platforms; profile **pictures**; cross-platform picture matching | WhatsMyName list, GitHub, Keybase, GitLab, Codeberg, npm, Hugging Face, crates.io, Docker Hub, Mastodon, Bluesky, Telegram, Steam, Reddit, Hacker News, DEV, Stack Overflow, Wikipedia, Lichess, Chess.com, Codeforces, Gravatar | Instagram, X, Facebook, TikTok, Threads, LinkedIn, Snapchat (login / anti-bot) → manual links |
| **Nickname / alias** | handle variants probed everywhere; exact-phrase web search | as above + Brave/Bing | — |
| **Full name** | candidate person records (employers, schools, location, interests, e-mail, websites, photo) from ORCID, Wikidata, OpenAlex, Crossref, Wikipedia, GitHub, personal sites and CV PDFs (names matched across Arabic/Latin spellings and nicknames), resolved into separate identities and scored against your other inputs; name dorks; derived usernames in aggressive mode | public registries, search engines | LinkedIn (blocks automated access; optional `-browser` reads the logged-out view where LinkedIn allows it, but e-mail and CV are never in that view: paste your own logged-in view), people-search sites, Facebook (login) → manual links |
| **E-mail** | mail provider & MX; Gravatar profile **and picture**; GitHub accounts publishing it (verified) and commits authored with it; stealer-log exposure (counts/dates only); verified web mentions; the domain behind it when not a public provider | DNS, Gravatar, GitHub, Hudson Rock public index, search engines | account-existence checks on other sites (holehe wrapper if installed), breach databases (paid) → manual links |
| **Phone** | validity, country, area, line type, original carrier, time zones, formats; verified web mentions | libphonenumber (offline), search engines | owner / caller-ID (Truecaller, Sync.ME need login) → manual links; WhatsApp/Telegram deep links |
| **Domain / URL** | DNS, SPF/DMARC/DKIM, mail provider, SaaS in use (TXT tokens), RDAP registration and contacts, subdomains (CT logs + passive DNS) resolved with wildcard detection, takeover candidates, website title/tech/headers/cookies/tracking IDs, contacts and social links on the site, robots/sitemap/security.txt, TLS certificate, archived sensitive-looking URLs, stealer-log counts | DNS, RDAP, crt.sh, certspotter, HackerTarget, Internet Archive, Hudson Rock, the site itself | historical DNS, reverse WHOIS, Shodan/Censys deep data (paid/login) → manual links |
| **IP** | reverse DNS, ASN, RDAP owner and abuse contact, approximate location, ports/CVEs already indexed by Shodan InternetDB (no scanning by rectool), GreyNoise classification, co-hosted domains, TLS certificate and web banner | DNS, RDAP, InternetDB, GreyNoise, HackerTarget | active port scanning (deliberately not done) |
| **ASN** | holder, announced prefixes, BGP neighbours, registration contacts | RIPEstat, RDAP | — |
| **Company** | likely websites verified against the page, official legal-entity records (GLEIF), Wikipedia/Wikidata, GitHub organisation, company dorks | GLEIF, Wikipedia, Wikidata, GitHub | OpenCorporates, Crunchbase, LinkedIn (CAPTCHA/login) → manual links |
| **Wallet (BTC / ETH)** | balance, transaction counts, first/last activity, contract status, ENS name, scam-report dorks | mempool.space, Blockscout | clustering and abuse databases (account) → manual links |
| **Location** | narrows searches, parses local phone numbers, corroborates profiles | — | — |

## Identity and accuracy

Facts are grouped per *person*, never blended across people who share a name or handle. See "Identity resolution" in the README for the rules (what links records, what never does, how scores and ✔ confirmations work). What the system will not do: pretend a name is enough. With only a common name it returns several candidates and says so; add a location, employer, e-mail or username and the best match separates from the rest.

## Pictures

Every profile picture found (about 22 sources plus Gravatar by e-mail) is downloaded by rectool itself, never by your browser, through an SSRF-guarded fetcher. Each gets a SHA-256 and a perceptual hash; **pictures that match across different sites are reported as a finding** ("Same profile picture on N sources"), which is strong evidence that accounts belong together. In a live audit, the GitHub avatar of `torvalds` and the Gravatar of `torvalds@linux-foundation.org` matched, tying the account to the e-mail address.

Default avatars, logos and generated placeholders are filtered. Always open the pictures: stock images and memes also repeat. Reverse image search links (Google Lens, Yandex, TinEye, Bing) are provided for each picture; rectool does not do face recognition.

## What can make a result missing

- **Rate limits and blocks.** Recorded per check and shown as *coverage gaps*. A failed check is never reported as "not found".
- **Connection-level failures** on username probes are retried once at low concurrency before being reported.
- **Stale site signatures.** Run `rectool -selftest-sites` periodically.
- **Services that were offline** during the run (the Internet Archive and crt.sh are intermittently down).
- **Search engines.** Google and DuckDuckGo usually block scrapers; Brave works best. Engines that block are skipped for the run.

## How confident to be

Each finding carries a confidence. Rules of thumb: ≥ 80 % is official/cross-checked data; 40–60 % is a handle or name match that might be someone else; unverified profile matches are explicitly labelled and never followed automatically. Treat the output as leads to verify, not as conclusions about a person.
