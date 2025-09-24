#!/usr/bin/env python3

# 此脚本连接MCP AI代理到Kali Linux终端和API服务器。



import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests

from mcp.server.fastmcp import FastMCP

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 默认配置
DEFAULT_KALI_SERVER = "http://localhost:5000" # 更改为你的Linux IP
DEFAULT_REQUEST_TIMEOUT = 300  # 默认API请求超时时间为5分钟

class KaliToolsClient:
    """与Kali Linux工具API服务器通信的客户端"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT, api_token: str = ""):
        """
        初始化Kali工具客户端
        
        参数:
            server_url: Kali工具API服务器的URL
            timeout: 请求超时时间（秒）
            api_token: 可选的API认证Bearer令牌
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.api_token = api_token.strip()
        self.headers = {"Authorization": f"Bearer {self.api_token}"} if self.api_token else None
        logger.info(f"已初始化Kali工具客户端，连接到 {server_url}")
        if self.api_token:
            logger.info("已启用API令牌认证用于Kali API请求")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        执行带有可选查询参数的GET请求。
        
        参数:
            endpoint: API端点路径（不带前导斜杠）
            params: 可选的查询参数
            
        返回:
            字典形式的响应数据
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"请求失败: {str(e)}")
            return {"error": f"请求失败: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"意外错误: {str(e)}")
            return {"error": f"意外错误: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行带有JSON数据的POST请求。
        
        参数:
            endpoint: API端点路径（不带前导斜杠）
            json_data: 要发送的JSON数据
            
        返回:
            字典形式的响应数据
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"请求失败: {str(e)}")
            return {"error": f"请求失败: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"意外错误: {str(e)}")
            return {"error": f"意外错误: {str(e)}", "success": False}

    def execute_command(self, command: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        在Kali服务器上执行通用命令
        
        参数:
            command: 要执行的命令
            timeout: 可选的每次请求超时时间（秒）
            
        返回:
            命令执行结果
        """
        payload: Dict[str, Any] = {"command": command}
        if timeout:
            payload["timeout"] = timeout
        return self.safe_post("api/command", payload)
    
    def check_health(self) -> Dict[str, Any]:
        """
        检查Kali工具API服务器的健康状态
        
        返回:
            健康状态信息
        """
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    设置MCP服务器并配置所有工具函数
    
    参数:
        kali_client: 已初始化的KaliToolsClient
        
    返回:
        配置好的FastMCP实例
    """
    mcp = FastMCP("kali-mcp")
    
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "", timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.
        
        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Scan results
        """
        data: Dict[str, Any] = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        if timeout:
            data["timeout"] = timeout
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "", timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.
        
        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Scan results
        """
        data: Dict[str, Any] = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        if timeout:
            data["timeout"] = timeout
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "", timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Scan results
        """
        data: Dict[str, Any] = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        if timeout:
            data["timeout"] = timeout
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "", timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Scan results
        """
        data: Dict[str, Any] = {
            "target": target,
            "additional_args": additional_args
        }
        if timeout:
            data["timeout"] = timeout
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "", timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Scan results
        """
        post_data: Dict[str, Any] = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        if timeout:
            post_data["timeout"] = timeout
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute a Metasploit module.
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Module execution results
        """
        data: Dict[str, Any] = {
            "module": module,
            "options": options
        }
        if timeout:
            data["timeout"] = timeout
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = "",
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Attack results
        """
        data: Dict[str, Any] = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        if timeout:
            data["timeout"] = timeout
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = "",
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Cracking results
        """
        data: Dict[str, Any] = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        if timeout:
            data["timeout"] = timeout
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "", timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Scan results
        """
        data: Dict[str, Any] = {
            "url": url,
            "additional_args": additional_args
        }
        if timeout:
            data["timeout"] = timeout
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a", timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Enumeration results
        """
        data: Dict[str, Any] = {
            "target": target,
            "additional_args": additional_args
        }
        if timeout:
            data["timeout"] = timeout
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.
        
        Returns:
            Server health information
        """
        return kali_client.check_health()
    
    @mcp.tool()
    def execute_command(command: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.
        
        Args:
            command: The command to execute
            timeout: Optional per-request timeout in seconds
            
        Returns:
            Command execution results
        """
        return kali_client.execute_command(command, timeout)

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--api-token", type=str, default=os.environ.get("KALI_API_TOKEN", ""),
                      help="Bearer token for authenticating with the Kali API (can also set KALI_API_TOKEN env var)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout, api_token=args.api_token)
    
    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")
    
    # Set up and run the MCP server
    mcp = setup_mcp_server(kali_client)
    logger.info("Starting Kali MCP server")
    mcp.run()

if __name__ == "__main__":
    main()
