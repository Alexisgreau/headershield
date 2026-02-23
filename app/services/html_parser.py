from __future__ import annotations
from urllib.parse import urljoin
from bs4 import BeautifulSoup


def analyze_mixed_content(soup: BeautifulSoup, page_url: str) -> list[tuple[str, str, str]]:
    """Finds mixed content issues in HTML. Returns (finding_type, tag, details)."""
    findings = []
    if not page_url.startswith("https://"):
        return []

    # Look for tags that can load external resources
    tags_with_src = soup.find_all(["img", "script", "iframe", "audio", "video", "source"])
    tags_with_href = soup.find_all(["link"])

    for tag in tags_with_src:
        if tag.has_attr("src"):
            resource_url = tag["src"]
            absolute_url = urljoin(page_url, resource_url)
            if absolute_url.startswith("http://"):
                findings.append(
                    ("mixed-content", tag.name, f"Insecure resource '{absolute_url}' loaded via <{tag.name}> tag.")
                )

    for tag in tags_with_href:
        if tag.has_attr("href") and tag.get("rel") == ["stylesheet"]:
            resource_url = tag["href"]
            absolute_url = urljoin(page_url, resource_url)
            if absolute_url.startswith("http://"):
                findings.append(
                    ("mixed-content", tag.name, f"Insecure stylesheet '{absolute_url}' loaded via <{tag.name}> tag.")
                )
    return findings

def analyze_sri(soup: BeautifulSoup) -> list[tuple[str, str, str]]:
    """Finds missing Subresource Integrity attributes. Returns (finding_type, tag, details)."""
    findings = []
    tags = soup.find_all(["script", "link"])
    for tag in tags:
        is_external = False
        url = ""
        
        # Check for external scripts and stylesheets
        if tag.name == "script" and tag.has_attr("src"):
            url = tag["src"]
            if "://" in url:
                is_external = True
        elif tag.name == "link" and tag.has_attr("href") and tag.get("rel") == ["stylesheet"]:
            url = tag["href"]
            if "://" in url:
                is_external = True
        
        if is_external and not tag.has_attr("integrity"):
            findings.append(
                ("sri-missing", tag.name, f"External resource '{url}' is missing the 'integrity' attribute.")
            )
    return findings


def analyze_html(html_content: str, page_url: str) -> list[tuple[str, str, str]]:
    """Analyzes HTML content for security issues."""
    if not html_content or not page_url.startswith("https://"):
        return []
    
    soup = BeautifulSoup(html_content, "html.parser")
    
    all_findings = []
    all_findings.extend(analyze_mixed_content(soup, page_url))
    all_findings.extend(analyze_sri(soup))
    
    return all_findings

