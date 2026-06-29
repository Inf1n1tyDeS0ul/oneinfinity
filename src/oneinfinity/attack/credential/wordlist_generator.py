"""wordlist_generator.py — Company-specific wordlist generator (CeWL equivalent)."""
from __future__ import annotations

import logging
import re
import urllib.request
import urllib.parse
from typing import List, Set

log = logging.getLogger("oneinfinity.credential.wordlist")

# Common password patterns to augment scraped words
_BASE_SUFFIXES = ["1", "12", "123", "1234", "!", "@", "#", "2023", "2024", "2025"]
_SEASONS = ["Spring", "Summer", "Fall", "Winter", "Autumn"]
_COMMON_PASSWORDS = [
    "Password1!", "Welcome1!", "Admin123!", "P@ssw0rd", "Letmein1!",
    "Company1!", "Summer2024!", "Winter2024!", "January2024!",
]


class WordlistGenerator:
    """
    Generate target-specific wordlists by scraping the target website
    and applying common password mutation rules.

    No external dependencies — pure Python requests via urllib.
    """

    def __init__(
        self,
        min_word_len: int = 6,
        max_word_len: int = 24,
        max_words: int = 2000,
    ):
        self.min_word_len = min_word_len
        self.max_word_len = max_word_len
        self.max_words = max_words

    def from_url(self, url: str, depth: int = 2) -> List[str]:
        """Scrape words from target URL (CeWL-style). Returns password candidate list."""
        words: Set[str] = set()
        visited: Set[str] = set()
        self._crawl(url, depth, words, visited)
        candidates = self._apply_rules(words)
        candidates.extend(_COMMON_PASSWORDS)
        seen = set()
        result = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                result.append(c)
        return result[: self.max_words]

    def from_domain(self, domain: str) -> List[str]:
        """Generate wordlist from a domain name only (no crawling)."""
        company = domain.split(".")[0]
        words = {company, company.capitalize(), company.upper()}
        candidates = self._apply_rules(words)
        candidates.extend(_COMMON_PASSWORDS)
        seen = set()
        result = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                result.append(c)
        return result[:500]

    def generate(self, domain: str, max_words: int = 500) -> List[str]:
        """Convenience wrapper: generate wordlist from domain, capped at max_words.
        Tries crawling https://<domain> first; falls back to domain-only derivation.
        """
        url = domain if domain.startswith("http") else f"https://{domain}"
        try:
            words = self.from_url(url, depth=1)
        except Exception:
            words = self.from_domain(domain)
        return words[:max_words]

    def _crawl(self, url: str, depth: int, words: Set[str], visited: Set[str]) -> None:
        if depth < 0 or url in visited or len(visited) > 20:
            return
        visited.add(url)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; OneInfinity/1.0)"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read(256 * 1024).decode("utf-8", errors="replace")

            # Extract words
            text = re.sub(r"<[^>]+>", " ", html)
            for word in re.findall(r"[A-Za-z][A-Za-z0-9]{%d,%d}" % (
                self.min_word_len - 1, self.max_word_len - 1
            ), text):
                words.add(word)

            if depth > 0:
                base = urllib.parse.urlparse(url)
                for href in re.findall(r'href=["\'](/[^"\'<>]{1,100})["\']', html)[:10]:
                    full = f"{base.scheme}://{base.netloc}{href}"
                    self._crawl(full, depth - 1, words, visited)

        except Exception as exc:
            log.debug("Crawl failed for %s: %s", url, exc)

    def _apply_rules(self, words: Set[str]) -> List[str]:
        """Apply common password mutation rules to scraped words."""
        candidates: List[str] = []
        for word in sorted(words)[:200]:
            w = word.strip()
            if not w or len(w) < 4:
                continue
            candidates.append(w.capitalize())
            for suffix in _BASE_SUFFIXES:
                candidates.append(f"{w.capitalize()}{suffix}")
            for season in _SEASONS:
                candidates.append(f"{season}{w.capitalize()}")
            # Leet speak
            leet = w.lower().replace("a", "@").replace("o", "0").replace("e", "3").replace("i", "1")
            if leet != w.lower():
                candidates.append(leet.capitalize() + "!")
        return candidates
