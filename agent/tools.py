"""
SOC Agent Tools - External API Integration and Tool Management

This module provides a centralized registry for all external tools and APIs
used by the SOC agent for threat intelligence gathering.
"""

import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any, Union
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import validators


@dataclass
class ToolResult:
    """Standardized result format for all tool operations"""
    success: bool
    source: str
    data: Dict[str, Any]
    error: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class BaseTool(ABC):
    """Abstract base class for all security tools"""

    TOOL_NAME = "base"

    def __init__(self, api_key: str, config: Dict[str, Any] = None):
        self.api_key = api_key
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._session = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    @abstractmethod
    async def query_ip(self, ip: str) -> ToolResult:
        """Query IP reputation"""
        pass

    @abstractmethod
    async def query_url(self, url: str) -> ToolResult:
        """Query URL reputation"""
        pass

    @abstractmethod
    async def query_file_hash(self, file_hash: str) -> ToolResult:
        """Query file hash reputation"""
        pass


class VirusTotalTool(BaseTool):
    """VirusTotal API integration for threat intelligence"""

    TOOL_NAME = "virustotal"

    def __init__(self, api_key: str, config: Dict[str, Any] = None):
        super().__init__(api_key, config)
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.rate_limit = self.config.get('rate_limit', 4)
        self._rate_interval = 60.0 / self.rate_limit
        self._last_request_time = 0.0

    async def _enforce_rate_limit(self):
        """Wait if necessary to respect the per-minute rate limit."""
        import time
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._rate_interval:
            await asyncio.sleep(self._rate_interval - elapsed)
        self._last_request_time = time.monotonic()

    def _parse_ip_response(self, data: Dict[str, Any]) -> ToolResult:
        """Parse a VT IP response into a ToolResult."""
        reputation_score = 0.0
        indicators = []

        if data.get('response_code') == 1:
            detected_urls = data.get('detected_urls', [])
            detected_samples = (
                data.get('detected_communicating_samples', [])
                or data.get('detected_samples', [])
            )
            reputation_score = min(len(detected_urls) * 0.1 + len(detected_samples) * 0.2, 1.0)

            if detected_urls:
                indicators.append(f"Associated with {len(detected_urls)} malicious URLs")
            if detected_samples:
                indicators.append(f"Associated with {len(detected_samples)} malicious files")
            if data.get('as_owner'):
                indicators.append(f"ASN: {data['as_owner']}")
            if data.get('country'):
                indicators.append(f"Country: {data['country']}")

        return ToolResult(
            success=True, source="virustotal",
            data={'reputation_score': reputation_score, 'indicators': indicators, 'raw_response': data}
        )

    async def query_ip(self, ip: str) -> ToolResult:
        """Query IP reputation from VirusTotal"""
        try:
            ipaddress.ip_address(ip)

            if not self.api_key:
                return ToolResult(
                    success=False, source="virustotal",
                    data={}, error="VirusTotal API key not configured"
                )

            await self._enforce_rate_limit()
            url = f"{self.base_url}/ip-address/report"
            params = {
                'apikey': self.api_key,
                'ip': ip
            }

            async with self._session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_ip_response(data)
                else:
                    return ToolResult(
                        success=False, source="virustotal",
                        data={}, error=f"HTTP {response.status}"
                    )

        except Exception as e:
            return ToolResult(
                success=False,
                source="virustotal",
                data={},
                error=str(e)
            )

    async def query_url(self, url: str) -> ToolResult:
        """Query URL reputation from VirusTotal"""
        try:
            if not validators.url(url):
                raise ValueError("Invalid URL format")

            if not self.api_key:
                return ToolResult(
                    success=False, source="virustotal",
                    data={}, error="VirusTotal API key not configured"
                )

            await self._enforce_rate_limit()
            scan_url = f"{self.base_url}/url/scan"
            scan_params = {
                'apikey': self.api_key,
                'url': url
            }

            async with self._session.post(scan_url, data=scan_params) as scan_response:
                if scan_response.status != 200:
                    raise Exception(f"Scan submission failed: {scan_response.status}")

                scan_data = await scan_response.json()
                resource = scan_data.get('resource')

                # Wait briefly then get report
                await asyncio.sleep(2)

                report_url = f"{self.base_url}/url/report"
                report_params = {
                    'apikey': self.api_key,
                    'resource': resource
                }

                async with self._session.get(report_url, params=report_params) as report_response:
                    if report_response.status == 200:
                        data = await report_response.json()

                        reputation_score = 0.0
                        indicators = []

                        if data.get('response_code') == 1:
                            positives = data.get('positives', 0)
                            total = data.get('total', 1)

                            reputation_score = positives / total if total > 0 else 0.0

                            if positives > 0:
                                indicators.append(f"Detected as malicious by {positives}/{total} engines")

                        return ToolResult(
                            success=True,
                            source="virustotal",
                            data={
                                'reputation_score': reputation_score,
                                'indicators': indicators,
                                'raw_response': data
                            }
                        )

        except Exception as e:
            return ToolResult(
                success=False,
                source="virustotal",
                data={},
                error=str(e)
            )

    async def query_file_hash(self, file_hash: str) -> ToolResult:
        """Query file hash reputation from VirusTotal"""
        try:
            if not self.api_key:
                return ToolResult(
                    success=False, source="virustotal",
                    data={}, error="VirusTotal API key not configured"
                )

            await self._enforce_rate_limit()
            url = f"{self.base_url}/file/report"
            params = {
                'apikey': self.api_key,
                'resource': file_hash
            }

            async with self._session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    reputation_score = 0.0
                    indicators = []

                    if data.get('response_code') == 1:
                        positives = data.get('positives', 0)
                        total = data.get('total', 1)

                        reputation_score = positives / total if total > 0 else 0.0

                        if positives > 0:
                            indicators.append(f"Detected as malware by {positives}/{total} engines")

                        # Extract additional file info
                        if 'scan_date' in data:
                            indicators.append(f"Last scanned: {data['scan_date']}")

                    return ToolResult(
                        success=True,
                        source="virustotal",
                        data={
                            'reputation_score': reputation_score,
                            'indicators': indicators,
                            'raw_response': data
                        }
                    )

        except Exception as e:
            return ToolResult(
                success=False,
                source="virustotal",
                data={},
                error=str(e)
            )


class AbuseIPDBTool(BaseTool):
    """AbuseIPDB API integration for IP reputation checking"""

    TOOL_NAME = "abuseipdb"

    def __init__(self, api_key: str, config: Dict[str, Any] = None):
        super().__init__(api_key, config)
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def _parse_ip_response(self, data: Dict[str, Any]) -> ToolResult:
        ip_data = data.get('data', {})
        abuse_confidence = ip_data.get('abuseConfidencePercentage', 0)
        usage_type = ip_data.get('usageType', 'unknown')
        country = ip_data.get('countryCode', 'unknown')
        isp = ip_data.get('isp', 'unknown')
        total_reports = ip_data.get('totalReports', 0)

        reputation_score = abuse_confidence / 100.0
        indicators = []
        if abuse_confidence > 0:
            indicators.append(f"Abuse confidence: {abuse_confidence}%")
        if total_reports > 0:
            indicators.append(f"Total reports: {total_reports}")
        if usage_type != 'unknown':
            indicators.append(f"Usage type: {usage_type}")
        if isp != 'unknown':
            indicators.append(f"ISP: {isp}")
        if country != 'unknown':
            indicators.append(f"Country: {country}")

        return ToolResult(
            success=True, source="abuseipdb",
            data={'reputation_score': reputation_score, 'indicators': indicators, 'raw_response': data}
        )

    async def query_ip(self, ip: str) -> ToolResult:
        """Query IP reputation from AbuseIPDB"""
        try:
            ipaddress.ip_address(ip)

            if not self.api_key:
                return ToolResult(
                    success=False, source="abuseipdb",
                    data={}, error="AbuseIPDB API key not configured"
                )

            url = f"{self.base_url}/check"
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }

            async with self._session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_ip_response(data)

        except Exception as e:
            return ToolResult(
                success=False,
                source="abuseipdb",
                data={},
                error=str(e)
            )

    async def query_url(self, url: str) -> ToolResult:
        """AbuseIPDB doesn't support URL checking directly"""
        return ToolResult(
            success=False,
            source="abuseipdb",
            data={},
            error="URL checking not supported by AbuseIPDB"
        )

    async def query_file_hash(self, file_hash: str) -> ToolResult:
        """AbuseIPDB doesn't support file hash checking"""
        return ToolResult(
            success=False,
            source="abuseipdb",
            data={},
            error="File hash checking not supported by AbuseIPDB"
        )


class URLVoidTool(BaseTool):
    """URLVoid API integration for URL reputation checking"""

    def __init__(self, api_key: str, config: Dict[str, Any] = None):
        super().__init__(api_key, config)
        self.base_url = "https://api.urlvoid.com/1000"

    async def query_ip(self, ip: str) -> ToolResult:
        """URLVoid doesn't support direct IP checking"""
        return ToolResult(
            success=False,
            source="urlvoid",
            data={},
            error="IP checking not supported by URLVoid"
        )

    async def query_url(self, url: str) -> ToolResult:
        """Query URL reputation from URLVoid"""
        try:
            if not validators.url(url):
                raise ValueError("Invalid URL format")

            from urllib.parse import urlparse
            import xml.etree.ElementTree as ET

            domain = urlparse(url).netloc

            api_url = f"{self.base_url}/{self.api_key}/host/{domain}"

            async with self._session.get(api_url) as response:
                if response.status == 200:
                    body = await response.text()
                    indicators = []
                    reputation_score = 0.0

                    try:
                        root = ET.fromstring(body)
                        detections = root.findtext('.//detections')
                        engines_count = root.findtext('.//engines/count')
                        ip = root.findtext('.//ip')
                        country = root.findtext('.//country_name')

                        if detections and engines_count:
                            det = int(detections)
                            eng = int(engines_count)
                            reputation_score = det / eng if eng > 0 else 0.0
                            if det > 0:
                                indicators.append(f"Detected by {det}/{eng} engines")

                        if ip:
                            indicators.append(f"Resolves to {ip}")
                        if country:
                            indicators.append(f"Hosted in {country}")
                    except ET.ParseError:
                        indicators.append("URLVoid check completed (non-XML response)")

                    return ToolResult(
                        success=True,
                        source="urlvoid",
                        data={
                            'reputation_score': reputation_score,
                            'indicators': indicators,
                            'raw_response': {'status': 'checked', 'body_length': len(body)}
                        }
                    )
                else:
                    return ToolResult(
                        success=False,
                        source="urlvoid",
                        data={},
                        error=f"HTTP {response.status}"
                    )

        except Exception as e:
            return ToolResult(
                success=False,
                source="urlvoid",
                data={},
                error=str(e)
            )

    async def query_file_hash(self, file_hash: str) -> ToolResult:
        """URLVoid doesn't support file hash checking"""
        return ToolResult(
            success=False,
            source="urlvoid",
            data={},
            error="File hash checking not supported by URLVoid"
        )


class ShodanTool(BaseTool):
    """Shodan API integration for internet device scanning"""

    TOOL_NAME = "shodan"

    def __init__(self, api_key: str, config: Dict[str, Any] = None):
        super().__init__(api_key, config)
        self.base_url = "https://api.shodan.io"

    def _parse_ip_response(self, data: Dict[str, Any]) -> ToolResult:
        ports = data.get('ports', [])
        vulns = data.get('vulns', [])
        org = data.get('org', 'unknown')

        reputation_score = 0.0
        if len(ports) > 10:
            reputation_score += 0.3
        if vulns:
            reputation_score += min(len(vulns) * 0.15, 0.6)

        indicators = []
        if ports:
            indicators.append(f"Open ports: {len(ports)} ({', '.join(str(p) for p in ports[:8])})")
        if vulns:
            indicators.append(f"Known vulnerabilities: {', '.join(vulns[:5])}")
        if org != 'unknown':
            indicators.append(f"Organization: {org}")
        if data.get('os'):
            indicators.append(f"OS: {data['os']}")
        if data.get('city'):
            indicators.append(f"Location: {data['city']}, {data.get('country_code', '')}")

        return ToolResult(
            success=True, source="shodan",
            data={'reputation_score': min(reputation_score, 1.0), 'indicators': indicators, 'raw_response': data}
        )

    async def query_ip(self, ip: str) -> ToolResult:
        """Query IP information from Shodan"""
        try:
            ipaddress.ip_address(ip)

            if not self.api_key:
                return ToolResult(
                    success=False, source="shodan",
                    data={}, error="Shodan API key not configured"
                )

            url = f"{self.base_url}/shodan/host/{ip}"
            params = {'key': self.api_key}

            async with self._session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_ip_response(data)

        except Exception as e:
            return ToolResult(
                success=False,
                source="shodan",
                data={},
                error=str(e)
            )

    async def query_url(self, url: str) -> ToolResult:
        """Shodan doesn't support direct URL checking"""
        return ToolResult(
            success=False,
            source="shodan",
            data={},
            error="URL checking not supported by Shodan"
        )

    async def query_file_hash(self, file_hash: str) -> ToolResult:
        """Shodan doesn't support file hash checking"""
        return ToolResult(
            success=False,
            source="shodan",
            data={},
            error="File hash checking not supported by Shodan"
        )


class ToolRegistry:
    """
    Central registry for managing all security tools and APIs

    Provides a unified interface for threat intelligence gathering
    with automatic fallback and result aggregation.
    """

    def __init__(self, api_keys: Dict[str, str], config: Dict[str, Any] = None):
        self.api_keys = api_keys
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.tools = {}
        self._initialize_tools()

    def _initialize_tools(self):
        """Initialize tools that have API keys configured."""

        tool_classes = {
            'virustotal': VirusTotalTool,
            'abuseipdb': AbuseIPDBTool,
            'shodan': ShodanTool,
        }

        for name, cls in tool_classes.items():
            key = self.api_keys.get(name, '')
            self.tools[name] = cls(key or '', self.config.get(name, {}))

        if self.api_keys.get('urlvoid'):
            self.tools['urlvoid'] = URLVoidTool(
                self.api_keys['urlvoid'],
                self.config.get('urlvoid', {})
            )

        live = [n for n, t in self.tools.items() if t.api_key]
        unconfigured = [n for n, t in self.tools.items() if not t.api_key]
        self.logger.info(
            f"Initialized {len(self.tools)} tools: "
            f"configured={live or 'none'}, missing_keys={unconfigured or 'none'}"
        )

    async def _query_with_sessions(self, available_sources: List[str],
                                   method_name: str, *args) -> List[Union[ToolResult, Exception]]:
        """Open sessions for all tools, run queries concurrently, then close."""
        tools = [self.tools[s] for s in available_sources]
        for tool in tools:
            await tool.__aenter__()
        try:
            tasks = [getattr(tool, method_name)(*args) for tool in tools]
            return await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for tool in tools:
                await tool.__aexit__(None, None, None)

    async def query_ip_reputation(self, ip: str, sources: Optional[List[str]] = None) -> ToolResult:
        """Query IP reputation from all available sources"""
        if sources is None:
            sources = ['virustotal', 'abuseipdb', 'shodan']

        available_sources = [s for s in sources if s in self.tools]

        if not available_sources:
            return ToolResult(
                success=False,
                source="registry",
                data={},
                error="No tools available for IP reputation checking"
            )

        results = await self._query_with_sessions(available_sources, 'query_ip', ip)
        return self._aggregate_results(results, "ip_reputation")

    async def query_url_reputation(self, url: str, sources: Optional[List[str]] = None) -> ToolResult:
        """Query URL reputation from all available sources"""
        if sources is None:
            sources = ['virustotal', 'urlvoid']

        available_sources = [s for s in sources if s in self.tools]

        if not available_sources:
            return ToolResult(
                success=False,
                source="registry",
                data={},
                error="No tools available for URL reputation checking"
            )

        results = await self._query_with_sessions(available_sources, 'query_url', url)
        return self._aggregate_results(results, "url_reputation")

    async def query_file_reputation(self, file_hash: str, sources: Optional[List[str]] = None) -> ToolResult:
        """Query file hash reputation from all available sources"""
        if sources is None:
            sources = ['virustotal']

        available_sources = [s for s in sources if s in self.tools]

        if not available_sources:
            return ToolResult(
                success=False,
                source="registry",
                data={},
                error="No tools available for file reputation checking"
            )

        results = await self._query_with_sessions(available_sources, 'query_file_hash', file_hash)
        return self._aggregate_results(results, "file_reputation")

    def _aggregate_results(self, results: List[Union[ToolResult, Exception]],
                          query_type: str) -> ToolResult:
        """Aggregate results from multiple tools into a single result"""

        successful_results = [r for r in results if isinstance(r, ToolResult) and r.success]
        [r for r in results if isinstance(r, Exception) or (isinstance(r, ToolResult) and not r.success)]

        if not successful_results:
            return ToolResult(
                success=False,
                source="registry",
                data={},
                error=f"All {query_type} queries failed"
            )

        # Aggregate reputation scores (take maximum)
        max_reputation = max(r.data.get('reputation_score', 0.0) for r in successful_results)

        # Combine all indicators
        all_indicators = []
        for result in successful_results:
            indicators = result.data.get('indicators', [])
            for indicator in indicators:
                all_indicators.append(f"[{result.source}] {indicator}")

        # Calculate overall confidence
        total_queries = len(results)
        successful_queries = len(successful_results)
        confidence = successful_queries / total_queries if total_queries > 0 else 0.0

        return ToolResult(
            success=True,
            source="registry",
            data={
                'reputation_score': max_reputation,
                'indicators': all_indicators,
                'confidence': confidence,
                'sources_queried': [r.source for r in successful_results],
                'query_type': query_type,
                'individual_results': [r.data for r in successful_results]
            }
        )

    def get_available_tools(self) -> List[str]:
        """Get list of available tool names"""
        return list(self.tools.keys())

    def get_tool_capabilities(self) -> Dict[str, List[str]]:
        """Get capabilities of each tool"""
        capabilities = {}

        for name, tool in self.tools.items():
            tool_caps = []

            # Check which methods each tool supports based on implementation
            if hasattr(tool, 'query_ip') and name in ['virustotal', 'abuseipdb', 'shodan']:
                tool_caps.append('ip_reputation')
            if hasattr(tool, 'query_url') and name in ['virustotal', 'urlvoid']:
                tool_caps.append('url_reputation')
            if hasattr(tool, 'query_file_hash') and name in ['virustotal']:
                tool_caps.append('file_reputation')

            capabilities[name] = tool_caps

        return capabilities
