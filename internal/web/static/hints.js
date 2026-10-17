"use strict";

// Help text shown next to every option. Each entry says, in English and
// Arabic, what turning the option on (or filling the field in) will do.
window.RT = window.RT || {};

RT.HINTS = {
  // ------------------------------------------------------------- identifiers
  full_name: {
    en: "The person's full name. Runs name look-ups (Wikidata, ORCID, OpenAlex, GitHub users), name dorks on search engines (profiles, documents, CVs), and raises the confidence of any profile whose name matches.",
    ar: "الاسم الكامل للشخص. بيشغّل بحث بالاسم (Wikidata وORCID وOpenAlex وGitHub) وبحث dorks في محركات البحث (بروفايلات ومستندات وسير ذاتية)، وبيرفع ثقة أي بروفايل اسمه مطابق.",
  },
  username: {
    en: "A handle the person uses online. Probes 630+ platforms, pulls real profile data (GitHub, Keybase, npm, Telegram, Steam…), reads commit e-mails, and follows verified cross-links to other accounts.",
    ar: "اسم مستخدم بيستعمله الشخص. بيفحص أكتر من 630 منصة، وبيسحب بيانات البروفايل الحقيقية (GitHub وKeybase وnpm وTelegram وSteam…)، وبيقرأ إيميلات الـcommits، وبيتابع الروابط الموثّقة لحسابات تانية.",
  },
  alias: {
    en: "A nickname or 'known as' name. Generates handle variants (dark.knight, darkknight, dark_knight…), probes each everywhere, and searches the exact phrase on the web.",
    ar: "لقب أو اسم شهرة. بيولّد منه صيغ يوزرنيم (dark.knight وdarkknight…) ويفحص كل صيغة على المنصات، ويبحث عن العبارة بالظبط في الويب.",
  },
  email: {
    en: "Mail provider and MX, Gravatar profile, GitHub accounts and commits that use it, infostealer-exposure counts (counts only), web mentions verified by opening each page, and an investigation of its domain when it is not a public provider.",
    ar: "بيفحص مزوّد الإيميل والـMX، وبروفايل Gravatar، وحسابات وcommits على GitHub بنفس الإيميل، وظهور الإيميل في تسريبات infostealer (أعداد فقط)، وذكر الإيميل في الويب (بيتأكد بفتح كل صفحة)، وبيحقق في دومين الإيميل لو مش مزوّد عام زي Gmail.",
  },
  phone: {
    en: "International format (+CC…). Gives validity, country, area, line type (mobile/landline/VoIP), original carrier, time zones, all formats, and web mentions of the number verified on the page. Cannot reveal the owner by itself.",
    ar: "بالصيغة الدولية (+CC…). بيطلّع صلاحية الرقم والدولة والمنطقة ونوع الخط (موبايل/أرضي/VoIP) وشركة الاتصالات الأصلية والمناطق الزمنية وكل الصيغ، وذكر الرقم في الويب. مش بيكشف صاحب الرقم لوحده.",
  },
  domain: {
    en: "A domain, a website URL, or a pasted profile link. Domains get DNS, mail security, WHOIS/RDAP, subdomains, tech stack, contacts on the site, TLS, archived URLs, exposure and takeover checks. A profile link (x.com/handle) becomes a username.",
    ar: "دومين أو رابط موقع أو رابط بروفايل. الدومين بيتفحص DNS وأمان الإيميل وWHOIS/RDAP والـsubdomains والتقنيات وبيانات التواصل في الموقع وشهادة TLS والأرشيف والتسريبات واحتمالات الاستيلاء. رابط البروفايل (x.com/handle) بيتحوّل ليوزرنيم.",
  },
  ip: {
    en: "An IPv4/IPv6 address. Reverse DNS, ASN, registration owner, approximate location, ports/CVEs already indexed by Shodan (no scanning by rectool), reputation, co-hosted domains and the TLS/web banner.",
    ar: "عنوان IP. بيطلّع الـreverse DNS والـASN وصاحب التسجيل والموقع التقريبي والبورتات والثغرات اللي مفهرسة عند Shodan (الأداة مش بتعمل scan)، والسمعة، والدومينات المشتركة، وبانر TLS والويب.",
  },
  asn: {
    en: "An autonomous system number (AS13335). Owner, announced IP prefixes, BGP neighbours and registration contacts.",
    ar: "رقم نظام مستقل (AS13335). بيطلّع المالك والـprefixes المعلنة وجيران BGP وجهات التسجيل.",
  },
  wallet: {
    en: "A Bitcoin or Ethereum/EVM address. Balance, transaction counts, first/last activity, contract status, ENS name, plus scam/abuse report dorks.",
    ar: "عنوان محفظة Bitcoin أو Ethereum. بيطلّع الرصيد وعدد المعاملات وأول وآخر نشاط ونوع العنوان واسم ENS، وبحث عن بلاغات النصب.",
  },
  company: {
    en: "An organisation name. Finds likely websites (verified against the live page), official legal-entity records (GLEIF), Wikipedia/Wikidata, the GitHub organisation, and company dorks (LinkedIn, registries, documents).",
    ar: "اسم شركة أو جهة. بيدوّر على مواقعها المحتملة (وبيتأكد من الصفحة نفسها) والسجلات الرسمية (GLEIF) وWikipedia/Wikidata ومنظمة GitHub وdorks خاصة بالشركات (LinkedIn وسجلات ومستندات).",
  },
  location: {
    en: "A city or country. Not an identifier by itself: it narrows name/company/alias searches, helps parse local-format phone numbers and corroborates profiles in the same place.",
    ar: "مدينة أو دولة. مش مدخل لوحده: بيضيّق البحث بالاسم والشركة واللقب، وبيساعد في تحليل أرقام الهاتف المحلية، وبيأكّد البروفايلات اللي في نفس المكان.",
  },

  // -------------------------------------------------------------- intensity
  aggressive: {
    en: "Maximum coverage. Derives usernames from the name, verifies social hits with a canary test, follows leads 3 rounds deep (up to 25 leads) and runs up to 120 dorks. Slower and sends many more requests, but finds the most.",
    ar: "أقصى تغطية. بيولّد يوزرنيمات من الاسم، وبيتحقق من نتايج السوشيال باختبار canary، وبيتابع الخيوط 3 جولات (لحد 25 خيط) وبيشغّل لحد 120 dork. أبطأ وبيبعت طلبات أكتر بكتير، لكن بيلاقي أكتر.",
  },
  verify: {
    en: "Re-tests each social hit with a random username. If the site reports that random name as existing too, the hit is a false positive and is dropped. About one extra request per hit.",
    ar: "بيعيد اختبار كل نتيجة سوشيال بيوزرنيم عشوائي. لو الموقع قال إن الاسم العشوائي موجود كمان يبقى النتيجة غلط وتتشال. تقريباً طلب زيادة لكل نتيجة.",
  },
  derive: {
    en: "Builds likely usernames from the full name (jdoe, john.doe, johnd…) and probes them. Adds many requests and some false positives unless 'Verify' is on.",
    ar: "بيولّد يوزرنيمات محتملة من الاسم الكامل (jdoe وjohn.doe…) ويفحصها. بيزوّد طلبات كتير وممكن نتايج غلط إلا لو 'Verify' شغّال.",
  },
  no_pivot: {
    en: "Stops after the first pass. Emails, domains, IPs and usernames that are discovered are listed but not investigated further.",
    ar: "بيوقف بعد الجولة الأولى. الإيميلات والدومينات والـIPs واليوزرنيمات اللي اتلاقت بتتعرض بس من غير ما تتحقق أكتر.",
  },
  proxies: {
    en: "Routes requests through these proxies in turn (http:// or socks5://, one per line) to hide your address or avoid rate limits. Leave empty to connect directly.",
    ar: "بيمرّر الطلبات عبر البروكسيات دي بالدور (http:// أو socks5:// وواحد في كل سطر) لإخفاء عنوانك أو تفادي الحظر. سيبها فاضية للاتصال المباشر.",
  },

  // ---------------------------------------------------------------- modules
  "mod:social": {
    en: "Needs a username/alias. Checks 630+ platforms by status code and page content, and adds title/bio/avatar when the page has them. Sends one request per site.",
    ar: "محتاج يوزرنيم/لقب. بيفحص أكتر من 630 منصة بكود الاستجابة ومحتوى الصفحة، وبيضيف العنوان والبايو والصورة لو موجودين. طلب واحد لكل موقع.",
  },
  "mod:profiles": {
    en: "Needs a username. Pulls structured profile data (real name, location, company, websites, e-mails, linked accounts) from ~20 platforms and scores each profile so unrelated people with the same handle are not mixed in.",
    ar: "محتاج يوزرنيم. بيسحب بيانات البروفايل (الاسم الحقيقي والمكان والشركة والمواقع والإيميلات والحسابات المرتبطة) من حوالي 20 منصة، وبيقيّم كل بروفايل عشان ما يتخلطش ناس مختلفين بنفس اليوزرنيم.",
  },
  "mod:domain": {
    en: "Needs a domain. DNS, SPF/DMARC, WHOIS/RDAP, subdomains, website tech, contacts, TLS, archived URLs, stealer-log counts and takeover candidates. Many requests to public sources and (lightly) to the site itself.",
    ar: "محتاج دومين. بيفحص DNS وSPF/DMARC وWHOIS والـsubdomains وتقنيات الموقع وبيانات التواصل وTLS والأرشيف وأعداد التسريبات واحتمالات الاستيلاء. طلبات كتير لمصادر عامة وطلبات خفيفة للموقع نفسه.",
  },
  "mod:ip": {
    en: "Needs an IP. Passive look-ups only: DNS, RDAP, Shodan InternetDB, GreyNoise, plus one TLS handshake and one web request to the address itself.",
    ar: "محتاج IP. بحث سلبي بس: DNS وRDAP وShodan InternetDB وGreyNoise، وطلب TLS واحد وطلب ويب واحد للعنوان نفسه.",
  },
  "mod:asn": {
    en: "Needs an ASN. Holder, announced prefixes, neighbours and contacts from RIPEstat and RDAP.",
    ar: "محتاج ASN. بيطلّع المالك والـprefixes والجيران وجهات التواصل من RIPEstat وRDAP.",
  },
  "mod:company": {
    en: "Needs a company name. Verified website candidates, GLEIF legal records, Wikipedia/Wikidata and GitHub org.",
    ar: "محتاج اسم شركة. مواقع محتملة متحقق منها، وسجلات GLEIF الرسمية، وWikipedia/Wikidata، ومنظمة GitHub.",
  },
  "mod:people": {
    en: "Needs a full name (2+ words). Low-confidence leads from Wikidata, ORCID, OpenAlex and GitHub name search.",
    ar: "محتاج اسم كامل (كلمتين أو أكتر). نتايج بثقة منخفضة من Wikidata وORCID وOpenAlex وبحث GitHub بالاسم.",
  },
  "mod:footprint": {
    en: "Needs an e-mail or phone. MX/provider, Gravatar, GitHub, stealer-log exposure, and web mentions verified by fetching each result page.",
    ar: "محتاج إيميل أو هاتف. MX والمزوّد وGravatar وGitHub وظهور الإيميل في التسريبات، وذكره في الويب مع التأكد بفتح كل صفحة.",
  },
  "mod:phone": {
    en: "Needs a phone number. Offline libphonenumber analysis: validity, country, area, line type, carrier, time zones. Sends no requests.",
    ar: "محتاج رقم هاتف. تحليل offline بمكتبة libphonenumber: الصلاحية والدولة والمنطقة والنوع والشركة والمناطق الزمنية. مش بيبعت أي طلبات.",
  },
  "mod:crypto": {
    en: "Needs a wallet address. Reads public block explorers: balance, activity, ENS name.",
    ar: "محتاج عنوان محفظة. بيقرأ مستكشفات البلوكتشين العامة: الرصيد والنشاط واسم ENS.",
  },
  "mod:dorks": {
    en: "Works with any input. Generates search-engine dorks and scrapes Brave/Bing/DuckDuckGo/Google (slowly, rate-limited). Engines that block scraping are skipped. Results are leads to verify.",
    ar: "بيشتغل مع أي مدخل. بيولّد dorks ويسحب نتايج Brave/Bing/DuckDuckGo/Google ببطء. المحركات اللي بتحجب بتتخطى. النتايج دي خيوط محتاجة تأكيد.",
  },
  "mod:syswrap": {
    en: "Runs installed external tools (whois, dig, theHarvester, subfinder, whatweb, sherlock, maigret, holehe, phoneinfoga) and parses their output. Tools that are not installed are reported, not failed.",
    ar: "بيشغّل الأدوات الخارجية المتسطبة (whois وdig وtheHarvester وsubfinder وwhatweb وsherlock وmaigret وholehe وphoneinfoga) وبيحلل ناتجها. الأدوات غير المتسطبة بتتبلّغ بس.",
  },
};

// Plain-language names for finding categories (used in the tree and filters).
RT.CATEGORY_LABELS = {
  social: "Social accounts", profile: "Profiles", "email-account": "E-mail accounts", "social-links": "Social links on site",
  dns: "DNS", whois: "Registration", subdomain: "Subdomains", web: "Website", tech: "Technology", tls: "TLS",
  tracking: "Tracking IDs", contact: "Contacts", "email-security": "E-mail security", security: "Security headers",
  archive: "Archive", exposure: "Exposure", takeover: "Takeover risk", reputation: "Reputation", network: "Network",
  geo: "Geolocation", crypto: "Crypto", company: "Company", registry: "Official registry", reference: "Reference",
  website: "Websites", identity: "Identity leads", phone: "Phone", "email-domain": "E-mail domain", ip: "IP",
};
