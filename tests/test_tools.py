"""
Unit tests for agent/tools.py

Tests all threat intelligence tools with mocked API responses
to avoid requiring actual API keys during testing.
"""

import pytest
import asyncio
import aiohttp
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
import json

from agent.tools import (
    ToolResult, BaseTool, VirusTotalTool, AbuseIPDBTool, 
    URLVoidTool, ShodanTool, ToolRegistry
)


class TestToolResult:
    """Test ToolResult dataclass functionality"""
    
    def test_tool_result_creation(self):
        """Test basic ToolResult creation"""
        result = ToolResult(
            success=True,
            source="test",
            data={"key": "value"}
        )
        
        assert result.success is True
        assert result.source == "test"
        assert result.data == {"key": "value"}
        assert result.error is None
        assert isinstance(result.timestamp, datetime)
    
    def test_tool_result_with_error(self):
        """Test ToolResult creation with error"""
        result = ToolResult(
            success=False,
            source="test",
            data={},
            error="Test error"
        )
        
        assert result.success is False
        assert result.error == "Test error"


class TestVirusTotalTool:
    """Test VirusTotal API integration"""
    
    @pytest.fixture
    def vt_tool(self):
        """Create VirusTotal tool instance for testing"""
        return VirusTotalTool("test_api_key", {"rate_limit": 4})
    
    @pytest.mark.asyncio
    async def test_query_ip_success(self, vt_tool):
        """Test successful IP reputation query"""
        mock_response = {
            "response_code": 1,
            "detected_urls": [{"url": "http://malicious.com"}],
            "detected_samples": [{"sha256": "abc123"}]
        }
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
            
            async with vt_tool:
                result = await vt_tool.query_ip("192.168.1.1")
            
            assert result.success is True
            assert result.source == "virustotal"
            assert "reputation_score" in result.data
            assert "indicators" in result.data
            assert len(result.data["indicators"]) > 0
    
    @pytest.mark.asyncio
    async def test_query_ip_invalid(self, vt_tool):
        """Test IP query with invalid IP address"""
        async with vt_tool:
            result = await vt_tool.query_ip("invalid_ip")
        
        assert result.success is False
        assert "invalid" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_query_url_success(self, vt_tool):
        """Test successful URL reputation query"""
        scan_response = {"resource": "test_resource"}
        report_response = {
            "response_code": 1,
            "positives": 5,
            "total": 10
        }
        
        with patch('aiohttp.ClientSession.post') as mock_post, \
             patch('aiohttp.ClientSession.get') as mock_get, \
             patch('asyncio.sleep'):
            
            # Mock scan submission
            mock_scan_resp = AsyncMock()
            mock_scan_resp.status = 200
            mock_scan_resp.json = AsyncMock(return_value=scan_response)
            mock_post.return_value.__aenter__ = AsyncMock(return_value=mock_scan_resp)
            
            # Mock report retrieval
            mock_report_resp = AsyncMock()
            mock_report_resp.status = 200
            mock_report_resp.json = AsyncMock(return_value=report_response)
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_report_resp)
            
            async with vt_tool:
                result = await vt_tool.query_url("http://example.com")
            
            assert result.success is True
            assert result.data["reputation_score"] == 0.5  # 5/10
    
    @pytest.mark.asyncio
    async def test_query_file_hash_success(self, vt_tool):
        """Test successful file hash reputation query"""
        mock_response = {
            "response_code": 1,
            "positives": 3,
            "total": 10,
            "scan_date": "2023-01-01 12:00:00"
        }
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
            
            async with vt_tool:
                result = await vt_tool.query_file_hash("abc123def456")
            
            assert result.success is True
            assert result.data["reputation_score"] == 0.3  # 3/10


class TestAbuseIPDBTool:
    """Test AbuseIPDB API integration"""
    
    @pytest.fixture
    def abuseipdb_tool(self):
        """Create AbuseIPDB tool instance for testing"""
        return AbuseIPDBTool("test_api_key")
    
    @pytest.mark.asyncio
    async def test_query_ip_success(self, abuseipdb_tool):
        """Test successful IP reputation query"""
        mock_response = {
            "data": {
                "abuseConfidencePercentage": 75,
                "usageType": "isp",
                "countryCode": "US"
            }
        }
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
            
            async with abuseipdb_tool:
                result = await abuseipdb_tool.query_ip("192.168.1.1")
            
            assert result.success is True
            assert result.source == "abuseipdb"
            assert result.data["reputation_score"] == 0.75
            assert "Abuse confidence: 75%" in result.data["indicators"]
    
    @pytest.mark.asyncio
    async def test_query_url_not_supported(self, abuseipdb_tool):
        """Test that URL queries are not supported"""
        async with abuseipdb_tool:
            result = await abuseipdb_tool.query_url("http://example.com")
        
        assert result.success is False
        assert "not supported" in result.error
    
    @pytest.mark.asyncio
    async def test_query_file_hash_not_supported(self, abuseipdb_tool):
        """Test that file hash queries are not supported"""
        async with abuseipdb_tool:
            result = await abuseipdb_tool.query_file_hash("abc123")
        
        assert result.success is False
        assert "not supported" in result.error


class TestURLVoidTool:
    """Test URLVoid API integration"""
    
    @pytest.fixture
    def urlvoid_tool(self):
        """Create URLVoid tool instance for testing"""
        return URLVoidTool("test_api_key")
    
    @pytest.mark.asyncio
    async def test_query_url_success(self, urlvoid_tool):
        """Test successful URL reputation query"""
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
            
            async with urlvoid_tool:
                result = await urlvoid_tool.query_url("http://example.com")
            
            assert result.success is True
            assert result.source == "urlvoid"
    
    @pytest.mark.asyncio
    async def test_query_ip_not_supported(self, urlvoid_tool):
        """Test that IP queries are not supported"""
        async with urlvoid_tool:
            result = await urlvoid_tool.query_ip("192.168.1.1")
        
        assert result.success is False
        assert "not supported" in result.error


class TestShodanTool:
    """Test Shodan API integration"""
    
    @pytest.fixture
    def shodan_tool(self):
        """Create Shodan tool instance for testing"""
        return ShodanTool("test_api_key")
    
    @pytest.mark.asyncio
    async def test_query_ip_success(self, shodan_tool):
        """Test successful IP information query"""
        mock_response = {
            "ports": [22, 80, 443, 8080],
            "vulns": ["CVE-2021-1234"],
            "org": "Example ISP"
        }
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
            
            async with shodan_tool:
                result = await shodan_tool.query_ip("192.168.1.1")
            
            assert result.success is True
            assert result.source == "shodan"
            assert "Open ports: 4" in result.data["indicators"]
            assert "Known vulnerabilities: 1" in result.data["indicators"]
    
    @pytest.mark.asyncio
    async def test_query_url_not_supported(self, shodan_tool):
        """Test that URL queries are not supported"""
        async with shodan_tool:
            result = await shodan_tool.query_url("http://example.com")
        
        assert result.success is False
        assert "not supported" in result.error


class TestToolRegistry:
    """Test ToolRegistry functionality"""
    
    @pytest.fixture
    def registry(self):
        """Create ToolRegistry with test API keys"""
        api_keys = {
            "virustotal": "vt_test_key",
            "abuseipdb": "abuse_test_key",
            "shodan": "shodan_test_key"
        }
        return ToolRegistry(api_keys)
    
    def test_tool_initialization(self, registry):
        """Test that tools are properly initialized"""
        assert len(registry.tools) == 3
        assert "virustotal" in registry.tools
        assert "abuseipdb" in registry.tools
        assert "shodan" in registry.tools
    
    def test_get_available_tools(self, registry):
        """Test getting list of available tools"""
        tools = registry.get_available_tools()
        assert "virustotal" in tools
        assert "abuseipdb" in tools
        assert "shodan" in tools
    
    def test_get_tool_capabilities(self, registry):
        """Test getting tool capabilities"""
        capabilities = registry.get_tool_capabilities()
        
        assert "ip_reputation" in capabilities["virustotal"]
        assert "url_reputation" in capabilities["virustotal"]
        assert "file_reputation" in capabilities["virustotal"]
        
        assert "ip_reputation" in capabilities["abuseipdb"]
        assert "url_reputation" not in capabilities["abuseipdb"]
        
        assert "ip_reputation" in capabilities["shodan"]
        assert "url_reputation" not in capabilities["shodan"]
    
    @pytest.mark.asyncio
    async def test_query_ip_reputation_aggregation(self, registry):
        """Test IP reputation aggregation from multiple sources"""
        # Mock individual tool results
        vt_result = ToolResult(True, "virustotal", {"reputation_score": 0.8, "indicators": ["VT indicator"]})
        abuse_result = ToolResult(True, "abuseipdb", {"reputation_score": 0.6, "indicators": ["Abuse indicator"]})
        shodan_result = ToolResult(True, "shodan", {"reputation_score": 0.4, "indicators": ["Shodan indicator"]})
        
        with patch.object(registry.tools["virustotal"], "query_ip", return_value=vt_result), \
             patch.object(registry.tools["abuseipdb"], "query_ip", return_value=abuse_result), \
             patch.object(registry.tools["shodan"], "query_ip", return_value=shodan_result):
            
            result = await registry.query_ip_reputation("192.168.1.1")
            
            assert result.success is True
            assert result.source == "registry"
            assert result.data["reputation_score"] == 0.8  # Maximum of all scores
            assert len(result.data["indicators"]) == 3
            assert result.data["confidence"] == 1.0  # All queries successful
    
    @pytest.mark.asyncio
    async def test_query_with_no_available_tools(self):
        """Test querying when no tools are available"""
        empty_registry = ToolRegistry({})  # No API keys
        
        result = await empty_registry.query_ip_reputation("192.168.1.1")
        
        assert result.success is False
        assert "No tools available" in result.error
    
    @pytest.mark.asyncio
    async def test_partial_failure_handling(self, registry):
        """Test handling when some tools fail"""
        vt_result = ToolResult(True, "virustotal", {"reputation_score": 0.8, "indicators": ["VT indicator"]})
        abuse_error = ToolResult(False, "abuseipdb", {}, error="API error")
        
        with patch.object(registry.tools["virustotal"], "query_ip", return_value=vt_result), \
             patch.object(registry.tools["abuseipdb"], "query_ip", return_value=abuse_error), \
             patch.object(registry.tools["shodan"], "query_ip", side_effect=Exception("Network error")):
            
            result = await registry.query_ip_reputation("192.168.1.1")
            
            assert result.success is True  # At least one tool succeeded
            assert result.data["confidence"] < 1.0  # Not all tools succeeded
            assert len(result.data["sources_queried"]) == 1  # Only VT succeeded


class TestToolIntegration:
    """Integration tests for tool interactions"""
    
    @pytest.mark.asyncio
    async def test_tool_context_manager(self):
        """Test that tools properly manage aiohttp sessions"""
        tool = VirusTotalTool("test_key")
        
        async with tool:
            assert tool._session is not None
            assert isinstance(tool._session, aiohttp.ClientSession)
        
        # Session should be closed after exiting context
        assert tool._session.closed is True
    
    @pytest.mark.asyncio
    async def test_concurrent_tool_usage(self):
        """Test using multiple tools concurrently"""
        api_keys = {
            "virustotal": "vt_key",
            "abuseipdb": "abuse_key"
        }
        registry = ToolRegistry(api_keys)
        
        # Mock successful responses for both tools
        vt_result = ToolResult(True, "virustotal", {"reputation_score": 0.5, "indicators": []})
        abuse_result = ToolResult(True, "abuseipdb", {"reputation_score": 0.3, "indicators": []})
        
        with patch.object(registry.tools["virustotal"], "query_ip", return_value=vt_result), \
             patch.object(registry.tools["abuseipdb"], "query_ip", return_value=abuse_result):
            
            # This should work without issues
            result = await registry.query_ip_reputation("192.168.1.1")
            
            assert result.success is True
            assert len(result.data["sources_queried"]) == 2


# CLI Mock Demonstrations
class TestCLIMockInteractions:
    """Mock CLI interactions for manual testing and demonstration"""
    
    @pytest.mark.mock
    def test_virustotal_cli_mock(self):
        """Mock CLI interaction for VirusTotal tool"""
        print("\n=== VirusTotal CLI Mock Demo ===")
        print("Command: python -m agent.tools virustotal query_ip 192.168.1.100")
        print("Response:")
        print(json.dumps({
            "success": True,
            "source": "virustotal",
            "data": {
                "reputation_score": 0.75,
                "indicators": [
                    "Associated with 3 malicious URLs",
                    "Associated with 1 malicious files"
                ]
            },
            "timestamp": datetime.now().isoformat()
        }, indent=2))
    
    @pytest.mark.mock
    def test_abuseipdb_cli_mock(self):
        """Mock CLI interaction for AbuseIPDB tool"""
        print("\n=== AbuseIPDB CLI Mock Demo ===")
        print("Command: python -m agent.tools abuseipdb query_ip 192.168.1.100")
        print("Response:")
        print(json.dumps({
            "success": True,
            "source": "abuseipdb",
            "data": {
                "reputation_score": 0.85,
                "indicators": [
                    "Abuse confidence: 85%",
                    "Usage type: isp",
                    "Country: US"
                ]
            },
            "timestamp": datetime.now().isoformat()
        }, indent=2))
    
    @pytest.mark.mock
    def test_registry_cli_mock(self):
        """Mock CLI interaction for ToolRegistry"""
        print("\n=== ToolRegistry CLI Mock Demo ===")
        print("Command: python -m agent.tools registry query_ip 192.168.1.100")
        print("Response:")
        print(json.dumps({
            "success": True,
            "source": "registry",
            "data": {
                "reputation_score": 0.85,
                "indicators": [
                    "[virustotal] Associated with 3 malicious URLs",
                    "[abuseipdb] Abuse confidence: 85%",
                    "[shodan] Open ports: 5"
                ],
                "confidence": 1.0,
                "sources_queried": ["virustotal", "abuseipdb", "shodan"]
            },
            "timestamp": datetime.now().isoformat()
        }, indent=2)) 