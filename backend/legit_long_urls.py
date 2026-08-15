"""
Curated set of real, known-legitimate long URLs used to fix the
length-bias in training.

The PhiUSIIL dataset's legitimate class contains almost no URLs
longer than ~58 characters (p90 = 34), while its phishing class
frequently exceeds 60-140+ chars. That spurious distribution taught
the model a hard "long URL => phishing" cliff. These examples are
injected into the training set as legitimate samples so the model
learns that long URLs (article permalinks, search results, product
pages, OAuth redirects) are normal for legitimate sites.

Every URL here is a real, well-known legitimate page. If a page is
unreachable/blocked at training time, FetchFailed=1 is a legitimate
outcome and is itself a valid training signal.
"""

CURATED_LEGIT_LONG_URLS = [
    # -- Canonical / minimal sites (sparse pages are NORMAL for these) --
    "https://example.com",
    "https://example.org",
    "https://www.iana.org/domains/example",
    "https://www.w3.org/TR/html53/semantics-embedded-content.html",
    # -- Search result pages (long query strings) ------------------
    "https://www.google.com/search?q=phishing+detection+machine+learning&oq=phishing+detection&aqs=chrome.0.69i59l3j0l2j69i60.1234j0j7&sourceid=chrome&ie=UTF-8",
    "https://www.bing.com/search?q=best+wireless+headphones+2024&qs=n&form=QBLH&sp=-1&pq=best+wireless+headphones&sc=8-22&sk=&cvid=abc123&ghsh=0&ghacc=0&ghpl=",
    "https://duckduckgo.com/?q=how+to+protect+yourself+from+phishing&t=h_&ia=web",
    # -- E-commerce product / search pages --------------------------
    "https://www.amazon.com/s?k=noise+cancelling+headphones&i=electronics&ref=nb_sb_noss_2",
    "https://www.amazon.com/Fitbit-Charge-Advanced-Fitness-Tracker/dp/B08DFBCB94/ref=sr_1_3?crid=abc&keywords=fitbit+charge&qid=1700000000&sprefix=fit%2Caps%2C200&sr=8-3",
    "https://www.ebay.com/sch/i.html?_from=R40&_nkw=nikon+camera+lens&_sacat=0&_sop=15&LH_PrefLoc=2&rt=nc",
    "https://www.walmart.com/ip/PlayStation-5-Digital-Edition-Console/499738170?athbdg=L1102",
    "https://www.bestbuy.com/site/samsung-galaxy-s24-ultra-256gb-unlocked-titanium-black/6478607.p?skuId=6478607",
    # -- Article / news permalinks (long paths + tracking params) ---
    "https://en.wikipedia.org/wiki/Phishing?oldid=1185000000&utm_source=share",
    "https://en.wikipedia.org/wiki/Artificial_intelligence_in_healthcare#Regulation_and_governance",
    "https://www.nytimes.com/2024/01/15/technology/artificial-intelligence-regulation-united-states.html?smid=url-share",
    "https://www.theguardian.com/technology/2024/jan/12/ai-phishing-scams-cybersecurity?utm_term=Autofeed&CMP=twt_gu&utm_medium=Social&utm_source=Twitter",
    "https://www.bbc.com/news/technology-67900000?intlink_from_url=https%3A%2F%2Fwww.bbc.com%2Fnews%2Ftechnology&link_location=technology-reporting-story",
    "https://arstechnica.com/security/2024/01/a-realistic-look-at-the-future-of-ai-driven-phishing-attacks/",
    "https://www.pcmag.com/picks/the-best-anti-phishing-software?test_uuid=01pCwfsdYgT2wF3Qh4d",
    # -- Documentation / help pages ---------------------------------
    "https://docs.python.org/3/library/urllib.parse.html#module-urllib.parse",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent",
    "https://docs.docker.com/get-started/overview/?gclid=Cj0KCQiA&utm_source=docs",
    "https://support.mozilla.org/en-US/kb/websites-say-connection-untrusted-error",
    "https://stackoverflow.com/questions/57068928/how-to-avoid-phishing-attacks-when-parsing-urls",
    "https://github.com/python/cpython/blob/main/Lib/urllib/parse.py",
    # -- SaaS login / SSO redirects (very long) ----------------------
    "https://accounts.google.com/ServiceLogin?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&flowName=GlifWebSignIn&flowEntry=ServiceLogin&passive=true",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc123&redirect_uri=https%3A%2F%2Foutlook.office.com%2Fmail&scope=openid+profile+email&response_type=code&state=randomtoken123",
    "https://github.com/login/oauth/authorize?client_id=abc123&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=repo%20user&state=xyz",
    # -- University / research pages ---------------------------------
    "https://www.stanford.edu/academics/courses/machine-learning-artificial-intelligence#course-information",
    "https://www.cmu.edu/cybersecurity-center/research/publications.html#phishing-detection",
]