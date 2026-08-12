import re
import requests
import warnings

from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urlparse, urljoin
from tld import get_tld

warnings.filterwarnings(
    "ignore",
    category=XMLParsedAsHTMLWarning
)


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
                url,
                headers=headers,
                timeout=(3, 5),
                allow_redirects=True,
            )

            self.page_content = self.response.text

            self.soup = BeautifulSoup(
                self.page_content,
                "html.parser"
            )

        except requests.exceptions.Timeout:
            self.page_fetch_failed = True
            self.page_fetch_error = "Website response timed out."

        except requests.exceptions.RequestException as e:
            self.page_fetch_failed = True
            self.page_fetch_error = f"Website request failed: {str(e)}"

        except Exception as e:
            self.page_fetch_failed = True
            self.page_fetch_error = str(e)

    def safe_parse(self, url):
        try:
            return urlparse(url)
        except Exception:
            return None

    def get_url_length(self):
        return len(self.url) if self.url else 0

    def get_domain_length(self):
        return len(self.domain) if self.domain else 0

    def get_tld_length(self):
        try:
            tld = get_tld(
                self.url,
                fail_silently=True
            )
            return len(tld) if tld else 0
        except Exception:
            return 0

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

    def get_no_of_self_ref(self):
        if not self.soup or not self.parsed_url:
            return 0

        base_url = (
            f"{self.parsed_url.scheme}://"
            f"{self.parsed_url.netloc}"
        )

        count = 0

        for tag in self.soup.find_all(
            ["a", "link", "script", "img"]
        ):
            resource_url = (
                tag.get("href")
                or tag.get("src")
            )

            if resource_url:
                full_url = urljoin(
                    base_url,
                    resource_url
                )

                if full_url.startswith(base_url):
                    count += 1

        return count

    def get_no_of_external_ref(self):
        if not self.soup or not self.parsed_url:
            return 0

        base_url = (
            f"{self.parsed_url.scheme}://"
            f"{self.parsed_url.netloc}"
        )

        count = 0

        for tag in self.soup.find_all(
            ["a", "link", "script", "img"]
        ):
            resource_url = (
                tag.get("href")
                or tag.get("src")
            )

            if resource_url:
                full_url = urljoin(
                    base_url,
                    resource_url
                )

                parsed_url = urlparse(full_url)

                if (
                    not full_url.startswith(base_url)
                    and parsed_url.netloc
                ):
                    count += 1

        return count

    def is_https(self):
        return (
            1
            if (
                self.parsed_url
                and self.parsed_url.scheme.lower() == "https"
            )
            else 0
        )

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
                    p,
                    self.page_content
                )
                for p in patterns
            )
            else 0
        )

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

    def has_description(self):
        if not self.soup:
            return 0

        tag = self.soup.find(
            "meta",
            attrs={"name": "description"}
        )

        return (
            1
            if tag and tag.get("content", "").strip()
            else 0
        )

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

    def has_iframe(self):
        if not self.soup:
            return 0

        return (
            1
            if self.soup.find("iframe")
            else 0
        )

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
                    p,
                    self.url,
                    re.IGNORECASE
                )
                for p in patterns
            )
            else 0
        )

    def get_redirect_value(self):
        if not self.response:
            return 0

        return (
            1
            if len(self.response.history) > 0
            else 0
        )

    def extract_model_features(self):

        redirect_value = self.get_redirect_value()

        if redirect_value == 0:
            redirect_0 = 1
            redirect_1 = 0
        else:
            redirect_0 = 0
            redirect_1 = 1

        letter_ratio = self.get_letter_ratio_in_url()
        digit_ratio = self.get_digit_ratio_in_url()

        letter_to_digit_ratio = (
            letter_ratio /
            (digit_ratio + 1e-5)
        )

        return {
            "URLLength":
                self.get_url_length(),

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
        }

    def get_fetch_status(self):
        return {
            "page_analyzed":
                not self.page_fetch_failed,

            "page_fetch_failed":
                self.page_fetch_failed,

            "page_fetch_error":
                self.page_fetch_error,
        }