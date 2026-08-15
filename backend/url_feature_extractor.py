import re
import requests
import warnings
from datetime import datetime, timezone

import whois

from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urlparse, urljoin
from tld import get_tld


# Suppress BeautifulSoup XML warning caused by some website responses.
warnings.filterwarnings(
    "ignore",
    category=XMLParsedAsHTMLWarning
)


# ============================================================
# TRUSTED-DOMAIN ALLOWLIST
#
# Domains that are, by definition, legitimate hosts (big brand
# properties, banking/SSO portals, documentation sites). They
# routinely serve *very* long URLs (OAuth redirects, search
# results, article permalinks) that no phishing detector should
# penalize for length alone. When a URL's registered domain is in
# this list, length-derived features are dampened so URL length
# can never single-handedly push a known-legitimate host toward
# HIGH risk.
# ============================================================

TRUSTED_DOMAINS = {
    # Search / portals / web mail
    "google.com", "googleusercontent.com", "googleapis.com",
    "google.co.in", "google.co.uk", "google.de", "google.fr",
    "gmail.com", "accounts.google.com",
    "bing.com", "yahoo.com", "duckduckgo.com",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "microsoftonline.com", "office365.com", "sharepoint.com",
    "salesforce.com", "citi.com", "citigroup.com",
    "service-now.com", "servicenow.com", "okta.com", "auth0.com",
    "onelogin.com", "duosecurity.com", "forgerock.com",
    # E-commerce / retail
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
    "amazon.fr", "amazon.co.jp", "ebay.com", "walmart.com",
    "target.com", "bestbuy.com", "flipkart.com", "shopify.com",
    "etsy.com", "alibaba.com", "aliexpress.com",
    # Social / content / news
    "wikipedia.org", "wikimedia.org", "wiktionary.org",
    "github.com", "gitlab.com", "stackoverflow.com",
    "stackexchange.com", "reddit.com", "facebook.com",
    "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "youtube.com", "tiktok.com", "pinterest.com",
    "nytimes.com", "bbc.com", "bbc.co.uk", "cnn.com",
    "theguardian.com", "medium.com", "wordpress.com",
    "blogspot.com", "w3.org", "mozilla.org", "mozilla.com",
    "apple.com", "adobe.com", "cloudflare.com",
    # Banking / finance / payment (real official domains)
    "paypal.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "citibank.com", "hsbc.com", "icicibank.com", "hdfcbank.com",
    "sbi.co.in", "capitalone.com", "amex.com", "americanexpress.com",
    "stripe.com", "visa.com", "mastercard.com",
    # SaaS / dev tools / productivity
    "notion.so", "slack.com", "dropbox.com", "zoom.us",
    "atlassian.com", "jira.com", "figma.com", "canva.com",
    "spotify.com", "netflix.com", "disneyplus.com",
    "airbnb.com", "uber.com", "lyft.com",
    # Education / government (specific registrable domains, since
    # eTLD matching is domain-level, not TLD-level)
    "mit.edu", "stanford.edu", "harvard.edu", "berkeley.edu",
    "cmu.edu", "ox.ac.uk", "cam.ac.uk", "nih.gov",
    "whitehouse.gov", "cdc.gov", "irs.gov", "justice.gov",
}


def get_registered_domain(url):
    """
    Extract the registrable domain (e.g. 'amazon.com' from
    'www.amazon.com', 'google.co.in' from 'accounts.google.co.in')
    using the tld library. Returns None on any parsing failure so
    allowlist lookups degrade safely.
    """
    try:
        obj = get_tld(
            url,
            fail_silently=True,
            as_object=True,
        )
        if obj:
            return obj.fld.lower()
    except Exception:
        pass
    return None


def is_trusted_domain(url):
    """
    True when the URL's registrable domain is in the trusted
    allowlist. Used to dampen length-based features for hosts that
    are known-legitimate.
    """
    domain = get_registered_domain(url)
    if not domain:
        return False
    if domain in TRUSTED_DOMAINS:
        return True
    # Also match bare eTLD+1 wildcards like 'edu'/'gov' are handled
    # above by direct membership; nothing else is needed here.
    return False


def url_length_bucket(url, length):
    """
    Shared bucketing for URL length, used identically by the live
    extractor and by offline training so train/inference can never
    drift apart.

    Buckets:
      1 = short       (<= 45 chars)
      2 = medium      (46 - 90)
      3 = long        (91 - 140)
      4 = very long   (> 140)

    Trusted allowlisted domains are capped at bucket 2 (medium) so a
    300-char Google login redirect or a long Amazon search URL can
    never be flagged *for its length alone*.
    """
    if length <= 45:
        bucket = 1
    elif length <= 90:
        bucket = 2
    elif length <= 140:
        bucket = 3
    else:
        bucket = 4

    if is_trusted_domain(url):
        bucket = min(bucket, 2)

    return bucket


class URLFeatureExtractor:

    def __init__(self, url, timeout=5):
        self.url = url
        self.timeout = timeout

        self.parsed_url = self.safe_parse(url)

        self.domain = (
            self.parsed_url.netloc
            if self.parsed_url
            else ""
        )

        self.soup = None
        self.page_content = None
        self.response = None

        self.page_fetch_failed = False
        self.page_fetch_error = None

        self.fetch_page()

    # ============================================================
    # PAGE FETCHING
    # ============================================================

    def fetch_page(self):
        try:

            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/150.0 Safari/537.36"
                ),
                "Accept": (
                    "text/html,"
                    "application/xhtml+xml,"
                    "application/xml;q=0.9,"
                    "*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.9",
            }

            self.response = requests.get(
                self.url,
                headers=headers,
                timeout=(3, self.timeout),
                allow_redirects=True,
            )

            self.page_content = self.response.text

            self.soup = BeautifulSoup(
                self.page_content,
                "html.parser"
            )

        except requests.exceptions.Timeout:

            self.page_fetch_failed = True
            self.page_fetch_error = (
                "Website response timed out."
            )

        except requests.exceptions.RequestException as e:

            self.page_fetch_failed = True
            self.page_fetch_error = (
                f"Website request failed: {str(e)}"
            )

        except Exception as e:

            self.page_fetch_failed = True
            self.page_fetch_error = str(e)

    # ============================================================
    # URL PARSING
    # ============================================================

    def safe_parse(self, url):

        try:
            return urlparse(url)

        except Exception:
            return None

    # ============================================================
    # BASIC URL FEATURES
    # ============================================================

    def get_url_length(self):

        return (
            len(self.url)
            if self.url
            else 0
        )

    def get_url_length_bucket(self):
        """
        Bucket raw URL length into a small set of categorical bins
        instead of exposing an unbounded continuous value.

        Raw length is a poor standalone phishing signal: legitimate
        article permalinks, search results and product pages are
        routinely 60-140+ characters, while the PhiUSIIL training
        set contains almost no legitimate URLs above ~58 chars. That
        spurious distribution taught the old model a hard "long URL
        => phishing" cliff. Bucketing bounds the feature and forces
        the model to treat length as coarse context rather than an
        unbounded penalty.

        Buckets:
          1 = short       (<= 45 chars)
          2 = medium      (46 - 90)
          3 = long        (91 - 140)
          4 = very long   (> 140)

        Trusted allowlisted domains are capped at bucket 2 (medium)
        so a 300-char Google login redirect or a long Amazon search
        URL can never be flagged *for its length alone*.
        """
        return url_length_bucket(
            self.url,
            self.get_url_length(),
        )

    def get_domain_length(self):

        return (
            len(self.domain)
            if self.domain
            else 0
        )

    def get_tld_length(self):

        try:

            tld = get_tld(
                self.url,
                fail_silently=True
            )

            return (
                len(tld)
                if tld
                else 0
            )

        except Exception:
            return 0

    # ============================================================
    # URL CHARACTER RATIOS
    # ============================================================

    def get_letter_ratio_in_url(self):

        if not self.url:
            return 0

        letters = sum(
            c.isalpha()
            for c in self.url
        )

        return letters / len(self.url)

    def get_digit_ratio_in_url(self):

        if not self.url:
            return 0

        digits = sum(
            c.isdigit()
            for c in self.url
        )

        return digits / len(self.url)

    # ============================================================
    # PAGE STRUCTURE FEATURES
    # ============================================================

    def get_no_of_images(self):

        if not self.soup:
            return 0

        return len(
            self.soup.find_all("img")
        )

    def get_no_of_js(self):

        if not self.soup:
            return 0

        return len(
            self.soup.find_all("script")
        )

    def get_no_of_css(self):

        if not self.soup:
            return 0

        return len(
            self.soup.find_all(
                "link",
                {"rel": "stylesheet"}
            )
        )

    # ============================================================
    # REFERENCE FEATURES
    # ============================================================

    def get_base_url(self):

        if not self.parsed_url:
            return ""

        return (
            f"{self.parsed_url.scheme}://"
            f"{self.parsed_url.netloc}"
        )

    def get_no_of_self_ref(self):

        if not self.soup or not self.parsed_url:
            return 0

        base_url = self.get_base_url()

        if not base_url:
            return 0

        count = 0

        for tag in self.soup.find_all(
            ["a", "link", "script", "img"]
        ):

            resource_url = (
                tag.get("href")
                or tag.get("src")
            )

            if not resource_url:
                continue

            try:

                full_url = urljoin(
                    base_url,
                    resource_url
                )

                parsed_resource = urlparse(
                    full_url
                )

                # Compare actual hostnames instead of
                # using a simple string prefix.
                if (
                    parsed_resource.netloc
                    and parsed_resource.netloc.lower()
                    == self.parsed_url.netloc.lower()
                ):
                    count += 1

            except Exception:
                continue

        return count

    def get_no_of_external_ref(self):

        if not self.soup or not self.parsed_url:
            return 0

        base_url = self.get_base_url()

        if not base_url:
            return 0

        count = 0

        for tag in self.soup.find_all(
            ["a", "link", "script", "img"]
        ):

            resource_url = (
                tag.get("href")
                or tag.get("src")
            )

            if not resource_url:
                continue

            try:

                full_url = urljoin(
                    base_url,
                    resource_url
                )

                parsed_resource = urlparse(
                    full_url
                )

                if (
                    parsed_resource.netloc
                    and parsed_resource.netloc.lower()
                    != self.parsed_url.netloc.lower()
                ):
                    count += 1

            except Exception:
                continue

        return count

    # ============================================================
    # DOMAIN AGE (WHOIS)
    # ============================================================
    #
    # Domain age is one of the strongest real-world phishing
    # signals: phishing domains are typically registered days or
    # weeks before use, while legitimate sites are usually years
    # old. WHOIS lookups are slow and frequently fail (rate
    # limiting, registrar privacy, missing records), so this is
    # cached per-instance and reports failures explicitly via
    # DomainAgeUnknown rather than silently guessing.

    def get_domain_age_days(self):

        if not self.domain:
            return None

        try:

            record = whois.whois(
                self.domain,
                timeout=5,
            )

            creation_date = record.get("creation_date")

            # python-whois sometimes returns a list of dates
            # (multiple records) instead of a single value.
            if isinstance(creation_date, list):
                creation_date = (
                    creation_date[0]
                    if creation_date
                    else None
                )

            if not isinstance(creation_date, datetime):
                return None

            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(
                    tzinfo=timezone.utc
                )

            age_days = (
                datetime.now(timezone.utc) - creation_date
            ).days

            return max(age_days, 0)

        except Exception:
            # Includes whois.parser.PywhoisError, socket timeouts,
            # rate limiting, and unsupported/unknown TLDs.
            return None

    # ============================================================
    # HTTPS
    # ============================================================

    def is_https(self):

        return (
            1
            if (
                self.parsed_url
                and self.parsed_url.scheme.lower()
                == "https"
            )
            else 0
        )

    # ============================================================
    # OBFUSCATION
    # ============================================================

    def has_obfuscation(self):

        if not self.page_content:
            return 0

        patterns = [
            r"%[0-9a-fA-F]{2}",
            r"\\x[0-9a-fA-F]{2}",
            r"&#x[0-9a-fA-F]+;",
            r"javascript:",
            r"eval\(",
            r"document\.write",
            r"fromCharCode",
        ]

        return (
            1
            if any(
                re.search(
                    pattern,
                    self.page_content
                )
                for pattern in patterns
            )
            else 0
        )

    # ============================================================
    # TITLE
    # ============================================================

    def has_title(self):

        if not self.soup:
            return 0

        return (
            1
            if (
                self.soup.title
                and self.soup.title.string
                and self.soup.title.string.strip()
            )
            else 0
        )

    # ============================================================
    # DESCRIPTION
    # ============================================================

    def has_description(self):

        if not self.soup:
            return 0

        tag = self.soup.find(
            "meta",
            attrs={
                "name": "description"
            }
        )

        return (
            1
            if (
                tag
                and tag.get(
                    "content",
                    ""
                ).strip()
            )
            else 0
        )

    # ============================================================
    # SUBMIT BUTTON
    # ============================================================

    def has_submit_button(self):

        if not self.soup:
            return 0

        return (
            1
            if (
                self.soup.find(
                    "input",
                    {"type": "submit"}
                )
                or self.soup.find("button")
            )
            else 0
        )

    # ============================================================
    # SOCIAL NETWORK
    # ============================================================

    def has_social_net(self):

        if not self.soup:
            return 0

        pattern = (
            r"facebook|twitter|linkedin|"
            r"instagram|youtube|pinterest"
        )

        return (
            1
            if re.search(
                pattern,
                self.soup.decode(),
                re.IGNORECASE
            )
            else 0
        )

    # ============================================================
    # FAVICON
    # ============================================================

    def has_favicon(self):

        if not self.soup:
            return 0

        return (
            1
            if self.soup.find(
                "link",
                rel=re.compile(
                    "icon",
                    re.IGNORECASE
                )
            )
            else 0
        )

    # ============================================================
    # COPYRIGHT
    # ============================================================

    def has_copyright_info(self):

        if not self.soup:
            return 0

        return (
            1
            if re.search(
                r"copyright|©",
                self.soup.get_text(),
                re.IGNORECASE
            )
            else 0
        )

    # ============================================================
    # POPUP
    # ============================================================

    def has_popup_window(self):

        if not self.page_content:
            return 0

        return (
            1
            if re.search(
                r"window\.open\s*\(",
                self.page_content
            )
            else 0
        )

    # ============================================================
    # IFRAME
    # ============================================================

    def has_iframe(self):

        if not self.soup:
            return 0

        return (
            1
            if self.soup.find("iframe")
            else 0
        )

    # ============================================================
    # ABNORMAL URL
    # ============================================================

    def is_abnormal_url(self):

        if not self.url:
            return 0

        patterns = [
            r"@",
            r"//\w+@",
            r"\d+\.\d+\.\d+\.\d+",
            r"\.(exe|zip|rar|dll|js)$",
        ]

        return (
            1
            if any(
                re.search(
                    pattern,
                    self.url,
                    re.IGNORECASE
                )
                for pattern in patterns
            )
            else 0
        )

    # ============================================================
    # REDIRECT
    # ============================================================

    def get_redirect_value(self):

        if not self.response:
            return 0

        return (
            1
            if len(
                self.response.history
            ) > 0
            else 0
        )

    # ============================================================
    # MODEL FEATURES
    # ============================================================

    def extract_model_features(self):

        redirect_value = (
            self.get_redirect_value()
        )

        domain_age_days = (
            self.get_domain_age_days()
        )

        if redirect_value == 0:

            redirect_0 = 1
            redirect_1 = 0

        else:

            redirect_0 = 0
            redirect_1 = 1

        # --------------------------------------------------------
        # IMPROVED LETTER-TO-DIGIT RATIO
        # --------------------------------------------------------
        #
        # The old implementation was:
        #
        # letter_ratio / (digit_ratio + 1e-5)
        #
        # This can create extremely large values for URLs
        # containing few or no digits.
        #
        # We instead use the raw counts and cap the result.
        # --------------------------------------------------------

        if self.url:

            letter_count = sum(
                c.isalpha()
                for c in self.url
            )

            digit_count = sum(
                c.isdigit()
                for c in self.url
            )

            letter_to_digit_ratio = (
                letter_count /
                max(digit_count, 1)
            )

            # Prevent the feature from becoming
            # disproportionately large.
            letter_to_digit_ratio = min(
                letter_to_digit_ratio,
                10.0
            )

        else:

            letter_to_digit_ratio = 0

        # --------------------------------------------------------
        # RETURN EXACTLY THE 22 MODEL FEATURES
        # --------------------------------------------------------

        return {

            "URLLength":
                self.get_url_length_bucket(),

            "DomainLength":
                self.get_domain_length(),

            "TLDLength":
                self.get_tld_length(),

            "NoOfImage":
                self.get_no_of_images(),

            "NoOfJS":
                self.get_no_of_js(),

            "NoOfCSS":
                self.get_no_of_css(),

            "NoOfSelfRef":
                self.get_no_of_self_ref(),

            "NoOfExternalRef":
                self.get_no_of_external_ref(),

            "IsHTTPS":
                self.is_https(),

            "HasObfuscation":
                self.has_obfuscation(),

            "HasTitle":
                self.has_title(),

            "HasDescription":
                self.has_description(),

            "HasSubmitButton":
                self.has_submit_button(),

            "HasSocialNet":
                self.has_social_net(),

            "HasFavicon":
                self.has_favicon(),

            "HasCopyrightInfo":
                self.has_copyright_info(),

            "popUpWindow":
                self.has_popup_window(),

            "Iframe":
                self.has_iframe(),

            "Abnormal_URL":
                self.is_abnormal_url(),

            "LetterToDigitRatio":
                letter_to_digit_ratio,

            "Redirect_0":
                redirect_0,

            "Redirect_1":
                redirect_1,

            # A failed page load (timeout, DNS failure, connection
            # refused, blocked scraper, dead host, etc.) is itself a
            # signal worth the model seeing directly, rather than
            # being indistinguishable from a live page that simply
            # has zero images/scripts/etc. Short-lived or blocking
            # phishing infrastructure fails to fetch far more often
            # than legitimate sites do.
            "FetchFailed":
                1 if self.page_fetch_failed else 0,

            # Domain age is one of the strongest phishing signals in
            # practice. Capped at 3650 days (~10 years) so a 20-year-
            # old domain and a 10-year-old domain aren't wildly
            # different scaled values - past a certain point, "old"
            # is "old". DomainAgeUnknown is 1 whenever WHOIS data
            # wasn't available, so the model can tell "genuinely new
            # domain" apart from "we don't know" instead of both
            # collapsing to the same default number.
            "DomainAgeDays":
                min(domain_age_days, 3650)
                if domain_age_days is not None
                else 0,

            "DomainAgeUnknown":
                0 if domain_age_days is not None else 1,
        }

    # ============================================================
    # FETCH STATUS
    # ============================================================

    def get_fetch_status(self):

        return {

            "page_analyzed":
                not self.page_fetch_failed,

            "page_fetch_failed":
                self.page_fetch_failed,

            "page_fetch_error":
                self.page_fetch_error,
        }