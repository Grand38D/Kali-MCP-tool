#!/usr/bin/env python3

# 此脚本将MCP AI代理连接到Kali Linux终端和API服务器。
# FastAPI版本提供更好的性能和异步支持


import argparse
import json
import logging
import os
import socket
import subprocess
import sys
import traceback
import threading
from typing import Dict, Any, Optional, List, Union
import shlex
import re
import tempfile
from urllib.parse import urlparse
import ipaddress
from functools import wraps
import platform
import datetime

# FastAPI导入
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# 导入缓存支持
from functools import lru_cache



# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 配置
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 3 minutes default timeout
API_TOKEN = os.environ.get("API_TOKEN", "")
# Added: output truncation and concurrency controls

# 终端窗口配置
TERMINAL_WINDOW_ENABLED = True  # 是否启用终端窗口
TERMINAL_WINDOW_TITLE = "MCP Kali 命令执行窗口"  # 终端窗口标题
TERMINAL_COMMAND_FILE = "mcp_commands.log"  # 用于与终端窗口通信的文件
MAX_OUTPUT_CHARS = int(os.environ.get("MAX_OUTPUT_CHARS", "50000"))
MAX_CONCURRENT_COMMANDS = int(os.environ.get("MAX_CONCURRENT_COMMANDS", "5"))
CACHE_SIZE = int(os.environ.get("CACHE_SIZE", "100"))

# 创建信号量以限制并发命令执行
command_semaphore = threading.Semaphore(MAX_CONCURRENT_COMMANDS)

# 终端窗口进程
terminal_process = None

# 创建FastAPI应用
app = FastAPI(title="Kali API Server", description="API Server for Kali Linux", version="1.0.0")

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 身份验证
def verify_token(request: Request):
    if not API_TOKEN:
        return True
    
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    token_parts = auth_header.split()
    if len(token_parts) != 2 or token_parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization header format")
    
    token = token_parts[1]
    if token != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return True

# Pydantic models
class CommandRequest(BaseModel):
    command: str
    timeout: Optional[int] = None

class NmapRequest(BaseModel):
    target: str
    scan_type: str = "-sV"
    ports: str = ""
    additional_args: str = ""
    timeout: Optional[int] = None

class GobusterRequest(BaseModel):
    url: str
    mode: str = "dir"
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    additional_args: str = ""
    timeout: Optional[int] = 300  # 默认超时时间设为5分钟

class SQLMapRequest(BaseModel):
    url: str
    data: str = ""
    additional_args: str = ""
    timeout: Optional[int] = None

class NiktoRequest(BaseModel):
    target: str
    additional_args: str = ""
    timeout: Optional[int] = None

class WPScanRequest(BaseModel):
    target: str
    additional_args: str = ""
    timeout: Optional[int] = None

class DirbRequest(BaseModel):
    url: str
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    additional_args: str = ""
    timeout: Optional[int] = None

class HydraRequest(BaseModel):
    target: str
    service: str
    user_list: str
    password_list: str
    additional_args: str = ""
    timeout: Optional[int] = None

class MetasploitRequest(BaseModel):
    command: str
    timeout: Optional[int] = None

class NucleiRequest(BaseModel):
    target: str
    templates: str = ""
    additional_args: str = ""
    timeout: Optional[int] = None

class CommandExecutor:
    def __init__(self):
        self.process = None
        self.output_buffer = ""
        self.error_buffer = ""
        self.timed_out = False
        self.real_time_output = False
    
    def set_real_time_output(self, enabled=True):
        self.real_time_output = enabled

# 添加缓存装饰器
def cache_result(func):
    cache = {}
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # 创建缓存键
        key = str(args) + str(kwargs)
        
        # 如果结果已缓存，直接返回
        if key in cache:
            logger.info(f"Cache hit for {func.__name__}")
            return cache[key]
        
        # 否则执行函数并缓存结果
        result = await func(*args, **kwargs)
        
        # 限制缓存大小
        if len(cache) >= CACHE_SIZE:
            # 简单策略：清除整个缓存
            cache.clear()
        
        cache[key] = result
        return result
    
    # 添加清除缓存的方法
    wrapper.clear_cache = lambda: cache.clear()
    
    return wrapper

# 使用缓存装饰器
def cache_key(cmd, timeout=None):
    """创建可哈希的缓存键"""
    if isinstance(cmd, list):
        return ' '.join(cmd), timeout
    return cmd, timeout

# 创建自定义缓存
command_cache = {}

async def execute_command(cmd, timeout=None, show_in_terminal=True):
    """执行命令并返回输出。
    
    参数：
        cmd: 要执行的命令（列表或字符串）
        timeout: 命令超时时间（秒）
        show_in_terminal: 是否在终端中显示输出
    """
    acquired = False
    
    # 检查缓存
    cache_entry = None
    if not show_in_terminal and len(command_cache) < CACHE_SIZE:  # 只在不显示终端输出且缓存未满时尝试缓存
        key = cache_key(cmd, timeout)
        if key in command_cache:
            logger.info(f"Cache hit for command: {key[0]}")
            return command_cache[key]
        cache_entry = key
    
    try:
        # 获取信号量以限制并发命令
        acquired = command_semaphore.acquire(blocking=True)
        
        # 设置超时
        cmd_timeout = timeout or COMMAND_TIMEOUT
        
        # 执行命令
        cmd_list = cmd if isinstance(cmd, list) else shlex.split(cmd)
        cmd_str = ' '.join(cmd_list)
        logger.info(f"Executing command: {cmd_str}")
        
        # 准备命令日志文件路径
        command_log_path = os.path.join(os.getcwd(), TERMINAL_COMMAND_FILE)
        
        # 如果需要在终端显示，使用不同的进程创建方式
        if show_in_terminal and TERMINAL_WINDOW_ENABLED:
            # 在服务控制台中只显示命令执行状态，不显示详细输出
            logger.info(f"执行命令: {cmd_str} (输出重定向到终端窗口)")
            
            # 将命令写入日志文件，供终端窗口显示
            try:
                with open(command_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"\n\n{'='*80}\n")
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 执行命令: {cmd_str}\n")
                    f.write(f"{'='*80}\n\n")
            except Exception as e:
                logger.error(f"写入命令日志文件失败: {str(e)}")
                # 如果写入失败，回退到控制台显示
                print(f"\n[MCP] 执行命令: {cmd_str}\n", flush=True)
            
            # 创建进程
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        else:
            # 常规执行方式或终端窗口未启用
            print(f"\n[MCP] 执行命令: {cmd_str}\n", flush=True)
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        
        try:
            # 如果需要在终端显示，实时输出结果
            if show_in_terminal:
                # 创建读取输出的协程
                async def read_stream(stream, is_stdout=True):
                    output_lines = []
                    prefix = "[输出] " if is_stdout else "[错误] "
                    while True:
                        line = await stream.readline()
                        if not line:
                            break
                        try:
                            line_str = line.decode('utf-8').rstrip()
                            output_lines.append(line_str)
                            
                            # 根据终端窗口是否启用决定输出位置
                            if TERMINAL_WINDOW_ENABLED:
                                # 将输出写入日志文件
                                try:
                                    with open(command_log_path, 'a', encoding='utf-8') as f:
                                        f.write(f"{prefix}{line_str}\n")
                                        f.flush()  # 确保立即写入文件
                                except Exception as e:
                                    logger.error(f"写入命令输出到日志文件失败: {str(e)}")
                                    # 如果写入失败，回退到控制台显示
                                    print(f"{prefix}{line_str}", flush=True)
                            else:
                                # 直接输出到控制台
                                print(f"{prefix}{line_str}", flush=True)
                        except Exception as e:
                            logger.error(f"Error decoding output: {str(e)}")
                    return '\n'.join(output_lines)
                
                # 并行读取stdout和stderr
                stdout_task = asyncio.create_task(read_stream(process.stdout, True))
                stderr_task = asyncio.create_task(read_stream(process.stderr, False))
                
                # 等待进程完成或超时
                try:
                    await asyncio.wait_for(process.wait(), timeout=cmd_timeout)
                except asyncio.TimeoutError:
                    # 写入超时信息
                    if TERMINAL_WINDOW_ENABLED:
                        try:
                            with open(command_log_path, 'a', encoding='utf-8') as f:
                                f.write(f"\n[MCP] 命令执行超时 ({cmd_timeout}秒)\n")
                                f.flush()
                        except Exception:
                            print(f"\n[MCP] 命令执行超时 ({cmd_timeout}秒)\n", flush=True)
                    else:
                        print(f"\n[MCP] 命令执行超时 ({cmd_timeout}秒)\n", flush=True)
                    
                    logger.warning(f"命令执行超时 ({cmd_timeout}秒)")
                    raise
                
                # 获取完整输出
                stdout_str = await stdout_task
                stderr_str = await stderr_task
                
                # 写入命令完成状态
                status = "成功" if process.returncode == 0 else f"失败 (返回码: {process.returncode})"
                if TERMINAL_WINDOW_ENABLED:
                    try:
                        with open(command_log_path, 'a', encoding='utf-8') as f:
                            f.write(f"\n[MCP] 命令执行{status}\n")
                            f.flush()
                    except Exception:
                        print(f"\n[MCP] 命令执行{status}\n", flush=True)
                else:
                    print(f"\n[MCP] 命令执行{status}\n", flush=True)
                
                logger.info(f"命令执行{status}")
            else:
                # 常规执行方式
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=cmd_timeout)
                stdout_str = stdout.decode('utf-8')
                stderr_str = stderr.decode('utf-8')
            
            # 截断过长的输出
            if len(stdout_str) > MAX_OUTPUT_CHARS:
                stdout_str = stdout_str[:MAX_OUTPUT_CHARS] + "\n... (output truncated)"
            
            if len(stderr_str) > MAX_OUTPUT_CHARS:
                stderr_str = stderr_str[:MAX_OUTPUT_CHARS] + "\n... (output truncated)"
            
            result = {
                "command": ' '.join(cmd_list) if isinstance(cmd, list) else cmd,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "return_code": process.returncode,
                "timed_out": False,
                "success": process.returncode == 0
            }
            
            # 缓存结果
            if cache_entry is not None:
                command_cache[cache_entry] = result
                
            return result
        except asyncio.TimeoutError:
            # 命令超时，尝试终止进程
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                # 如果进程没有在5秒内终止，强制终止
                process.kill()
            
            result = {
                "command": ' '.join(cmd_list) if isinstance(cmd, list) else cmd,
                "stdout": "",
                "stderr": "Command timed out after {} seconds".format(cmd_timeout),
                "return_code": None,
                "timed_out": True,
                "success": False
            }
            
            # 不缓存超时结果
            return result
    finally:
        # 释放信号量
        if acquired:
            command_semaphore.release()

# Helper functions
def is_valid_url(url):
    """检查URL是否有效。"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_valid_ip(ip):
    """检查IP是否有效。"""
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def is_valid_hostname(hostname):
    """检查主机名是否有效。"""
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def is_valid_target(target):
    """检查目标是否有效。"""
    return is_valid_ip(target) or is_valid_hostname(target) or is_valid_url(target)

def is_valid_ports(ports):
    """检查端口字符串是否有效。"""
    # 允许的格式：单个端口(80)、端口范围(80-100)、端口列表(80,443,8080)或它们的组合
    port_pattern = r'^(?:\d+|\d+-\d+)(?:,(?:\d+|\d+-\d+))*$'
    return re.match(port_pattern, ports) is not None

def split_args(args_str):
    """Split a string into command line arguments."""
    if not args_str:
        return []
    return shlex.split(args_str)

# API endpoints
@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Kali API Server is running"}

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}

@app.get("/api/capabilities")
async def capabilities(_: bool = Depends(verify_token)):
    """Return the capabilities of the API."""
    return {
        "tools": [
            "nmap",
            "gobuster",
            "sqlmap",
            "nikto",
            "wpscan",
            "dirb",
            "hydra",
            "metasploit",
            "nuclei"
        ],
        "streaming_endpoints": {
            "command": "/api/command/stream",
            "nmap": "/api/tools/nmap/stream",
            "nuclei": "/api/tools/nuclei/stream"
        },
        "cache_size": CACHE_SIZE
    }

@app.post("/api/command")
async def generic_command(request: CommandRequest, _: bool = Depends(verify_token)):
    """Execute any command provided in the request."""
    try:
        command = request.command
        timeout = request.timeout
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            raise HTTPException(status_code=400, detail="Command parameter is required")
        
        result = await execute_command(shlex.split(command), timeout, show_in_terminal=True)
        return result
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/command/stream")
async def stream_command(request: CommandRequest, _: bool = Depends(verify_token)):
    """Execute command with streaming output."""
    from fastapi.responses import StreamingResponse
    import asyncio
    import json
    
    try:
        command = request.command
        timeout = request.timeout
        
        if not command:
            logger.warning("Stream command endpoint called without command parameter")
            raise HTTPException(status_code=400, detail="Command parameter is required")
        
        async def generate_output():
            cmd_list = shlex.split(command) if isinstance(command, str) else list(command)
            
            # 创建异步子进程
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                text=True
            )
            
            # 用于跟踪命令执行状态
            status = {
                "command": command,
                "status": "running",
                "return_code": None,
                "timed_out": False
            }
            
            # 发送初始状态
            yield json.dumps(status) + "\n"
            
            # 设置超时
            cmd_timeout = timeout or COMMAND_TIMEOUT
            
            # 读取输出的协程
            async def read_stream(stream, stream_name):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    try:
                        line_str = line.decode('utf-8')
                        output = {
                            "stream": stream_name,
                            "data": line_str.rstrip()
                        }
                        yield json.dumps(output) + "\n"
                    except Exception as e:
                        logger.error(f"Error decoding output: {str(e)}")
            
            # 创建读取任务
            stdout_task = asyncio.create_task(read_stream(process.stdout, "stdout"))
            stderr_task = asyncio.create_task(read_stream(process.stderr, "stderr"))
            
            try:
                # 等待进程完成或超时
                try:
                    return_code = await asyncio.wait_for(process.wait(), timeout=cmd_timeout)
                    status["status"] = "completed"
                    status["return_code"] = return_code
                    status["success"] = return_code == 0
                except asyncio.TimeoutError:
                    # 进程超时
                    status["status"] = "timeout"
                    status["timed_out"] = True
                    status["success"] = False
                    # 尝试终止进程
                    try:
                        process.terminate()
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        # 强制终止
                        process.kill()
                
                # 等待输出读取完成
                async for line in stdout_task:
                    yield line
                async for line in stderr_task:
                    yield line
                
                # 发送最终状态
                yield json.dumps(status) + "\n"
                
            except Exception as e:
                logger.error(f"Error in streaming: {str(e)}")
                error_status = {
                    "status": "error",
                    "error": str(e),
                    "success": False
                }
                yield json.dumps(error_status) + "\n"
        
        return StreamingResponse(
            generate_output(),
            media_type="application/x-ndjson"
        )
    except Exception as e:
        logger.error(f"Error in stream command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/nmap")
async def nmap(request: NmapRequest, _: bool = Depends(verify_token)):
    """Execute nmap scan with the provided parameters."""
    try:
        target = request.target.strip()
        scan_type = request.scan_type
        ports = request.ports.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not target:
            logger.warning("Nmap called without target parameter")
            raise HTTPException(status_code=400, detail="Target parameter is required")
        
        cmd = ["nmap"] + split_args(scan_type)
        
        if ports:
            if not is_valid_ports(ports):
                logger.warning(f"Invalid ports format: {ports}")
                raise HTTPException(status_code=400, detail="Invalid ports format")
            cmd.extend(["-p", ports])
        
        if additional_args:
            cmd.extend(split_args(additional_args))
        
        cmd.append(target)
        
        result = await execute_command(cmd, timeout, show_in_terminal=True)
        return result
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/nmap/stream")
async def nmap_stream(request: NmapRequest, _: bool = Depends(verify_token)):
    """Execute nmap scan with streaming output."""
    from fastapi.responses import StreamingResponse
    import asyncio
    import json
    
    try:
        target = request.target.strip()
        scan_type = request.scan_type
        ports = request.ports.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not target:
            logger.warning("Nmap stream called without target parameter")
            raise HTTPException(status_code=400, detail="Target parameter is required")
        
        cmd = ["nmap"] + split_args(scan_type)
        
        if ports:
            if not is_valid_ports(ports):
                logger.warning(f"Invalid ports format: {ports}")
                raise HTTPException(status_code=400, detail="Invalid ports format")
            cmd.extend(["-p", ports])
        
        if additional_args:
            cmd.extend(split_args(additional_args))
        
        cmd.append(target)
        
        async def generate_output():
            # 创建异步子进程
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # 用于跟踪命令执行状态
            status = {
                "command": ' '.join(cmd),
                "status": "running",
                "return_code": None,
                "timed_out": False
            }
            
            # 发送初始状态
            yield json.dumps(status) + "\n"
            
            # 设置超时
            cmd_timeout = timeout or COMMAND_TIMEOUT
            
            # 读取输出的协程
            async def read_stream(stream, stream_name):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    try:
                        line_str = line.decode('utf-8')
                        output = {
                            "stream": stream_name,
                            "data": line_str.rstrip()
                        }
                        yield json.dumps(output) + "\n"
                    except Exception as e:
                        logger.error(f"Error decoding output: {str(e)}")
            
            # 创建读取任务
            stdout_task = asyncio.create_task(read_stream(process.stdout, "stdout"))
            stderr_task = asyncio.create_task(read_stream(process.stderr, "stderr"))
            
            try:
                # 等待进程完成或超时
                try:
                    return_code = await asyncio.wait_for(process.wait(), timeout=cmd_timeout)
                    status["status"] = "completed"
                    status["return_code"] = return_code
                    status["success"] = return_code == 0
                except asyncio.TimeoutError:
                    # 进程超时
                    status["status"] = "timeout"
                    status["timed_out"] = True
                    status["success"] = False
                    # 尝试终止进程
                    try:
                        process.terminate()
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        # 强制终止
                        process.kill()
                
                # 等待输出读取完成
                async for line in stdout_task:
                    yield line
                async for line in stderr_task:
                    yield line
                
                # 发送最终状态
                yield json.dumps(status) + "\n"
                
            except Exception as e:
                logger.error(f"Error in streaming: {str(e)}")
                error_status = {
                    "status": "error",
                    "error": str(e),
                    "success": False
                }
                yield json.dumps(error_status) + "\n"
        
        return StreamingResponse(
            generate_output(),
            media_type="application/x-ndjson"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in nmap stream endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/gobuster")
async def gobuster(request: GobusterRequest, _: bool = Depends(verify_token)):
    """使用提供的参数执行gobuster。"""
    try:
        url = request.url.strip()
        mode = request.mode.strip()
        wordlist = request.wordlist.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            raise HTTPException(status_code=400, detail="URL parameter is required")
        
        if not is_valid_url(url):
            logger.warning(f"无效的URL格式: {url}")
            raise HTTPException(status_code=400, detail="无效的URL格式")
        
        cmd = ["gobuster", mode, "-u", url, "-w", wordlist]
        
        # 处理额外参数
        if additional_args:
            # 过滤掉 -p 参数
            args_list = split_args(additional_args)
            filtered_args = []
            i = 0
            while i < len(args_list):
                # 检查是否为 -p 或 -p- 参数
                if args_list[i] in ["-p", "-p-"]:
                    logger.warning(f"Blocked restricted gobuster parameter: {args_list[i]}")
                    i += 1  # 跳过该参数
                    # 如果后面还有值且不是以-开头，也跳过（可能是参数值）
                    if i < len(args_list) and not args_list[i].startswith('-'):
                        i += 1
                else:
                    filtered_args.append(args_list[i])
                    i += 1
            
            cmd.extend(filtered_args)
        
        logger.info(f"执行 gobuster 命令，超时设置为: {timeout} 秒")
        result = await execute_command(cmd, timeout, show_in_terminal=True)
        return result
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/sqlmap")
async def sqlmap(request: SQLMapRequest, _: bool = Depends(verify_token)):
    """使用提供的参数执行sqlmap。"""
    try:
        url = request.url.strip()
        data = request.data.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            raise HTTPException(status_code=400, detail="URL parameter is required")
        
        if not is_valid_url(url):
            logger.warning(f"无效的URL格式: {url}")
            raise HTTPException(status_code=400, detail="无效的URL格式")
        
        cmd = ["sqlmap", "-u", url]
        
        if data:
            cmd.extend(["--data", data])
        
        if additional_args:
            cmd.extend(split_args(additional_args))
        
        result = await execute_command(cmd, timeout, show_in_terminal=True)
        return result
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/nikto")
async def nikto(request: NiktoRequest, _: bool = Depends(verify_token)):
    """使用提供的参数执行nikto。"""
    try:
        target = request.target.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not target:
            logger.warning("Nikto called without target parameter")
            raise HTTPException(status_code=400, detail="Target parameter is required")
        
        cmd = ["nikto", "-h", target]
        
        if additional_args:
            cmd.extend(split_args(additional_args))
        
        result = await execute_command(cmd, timeout, show_in_terminal=True)
        return result
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/wpscan")
async def wpscan(request: WPScanRequest, _: bool = Depends(verify_token)):
    """Execute wpscan with the provided parameters."""
    try:
        target = request.target.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not target:
            logger.warning("WPScan called without target parameter")
            raise HTTPException(status_code=400, detail="Target parameter is required")
        
        if not is_valid_url(target):
            logger.warning(f"无效的URL格式: {target}")
            raise HTTPException(status_code=400, detail="无效的URL格式")
        
        cmd = ["wpscan", "--url", target]
        
        if additional_args:
            cmd.extend(split_args(additional_args))
        
        result = await execute_command(cmd, timeout, show_in_terminal=True)
        return result
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/dirb")
async def dirb(request: DirbRequest, _: bool = Depends(verify_token)):
    """使用提供的参数执行dirb。"""
    try:
        url = request.url.strip()
        wordlist = request.wordlist.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            raise HTTPException(status_code=400, detail="URL parameter is required")
        
        if not is_valid_url(url):
            logger.warning(f"无效的URL格式: {url}")
            raise HTTPException(status_code=400, detail="无效的URL格式")
        
        cmd = ["dirb", url, wordlist]
        
        if additional_args:
            cmd.extend(split_args(additional_args))
        
        result = await execute_command(cmd, timeout, show_in_terminal=True)
        return result
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/hydra")
async def hydra(request: HydraRequest, _: bool = Depends(verify_token)):
    """Execute hydra with the provided parameters."""
    try:
        target = request.target.strip()
        service = request.service.strip()
        user_list = request.user_list.strip()
        password_list = request.password_list.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not target or not service or not user_list or not password_list:
            logger.warning("Hydra called with missing parameters")
            raise HTTPException(status_code=400, detail="Target, service, user_list, and password_list parameters are required")
        
        # 创建临时文件存储用户名和密码列表
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as user_file:
            user_file.write(user_list)
            user_file_path = user_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as pass_file:
            pass_file.write(password_list)
            pass_file_path = pass_file.name
        
        cmd = ["hydra", "-L", user_file_path, "-P", pass_file_path, target, service]
        
        if additional_args:
            cmd.extend(split_args(additional_args))
        
        try:
            result = await execute_command(cmd, timeout, show_in_terminal=True)
        finally:
            # 清理临时文件
            try:
                os.unlink(user_file_path)
                os.unlink(pass_file_path)
            except:
                pass
        
        return result
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/metasploit")
async def metasploit(request: MetasploitRequest, _: bool = Depends(verify_token)):
    """Execute metasploit commands."""
    try:
        command = request.command.strip()
        timeout = request.timeout
        
        if not command:
            logger.warning("Metasploit called without command parameter")
            raise HTTPException(status_code=400, detail="Command parameter is required")
        
        # 创建临时文件存储命令
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as cmd_file:
            cmd_file.write(command)
            cmd_file_path = cmd_file.name
        
        cmd = ["msfconsole", "-q", "-r", cmd_file_path]
        
        try:
            result = await execute_command(cmd, timeout, show_in_terminal=True)
        finally:
            # 清理临时文件
            try:
                os.unlink(cmd_file_path)
            except:
                pass
        
        return result
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/nuclei")
async def nuclei(request: NucleiRequest, _: bool = Depends(verify_token)):
    """Execute nuclei with the provided parameters."""
    try:
        target = request.target.strip()
        templates = request.templates.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not target:
            logger.warning("Nuclei called without target parameter")
            raise HTTPException(status_code=400, detail="Target parameter is required")
        
        cmd = ["nuclei", "-target", target]
        
        if templates:
            cmd.extend(["-t", templates])
        
        if additional_args:
            cmd.extend(split_args(additional_args))
        
        result = await execute_command(cmd, timeout, show_in_terminal=True)
        return result
    except Exception as e:
        logger.error(f"Error in nuclei endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/tools/nuclei/stream")
async def nuclei_stream(request: NucleiRequest, _: bool = Depends(verify_token)):
    """Execute nuclei scan with streaming output."""
    from fastapi.responses import StreamingResponse
    import asyncio
    import json
    
    try:
        target = request.target.strip()
        templates = request.templates.strip()
        additional_args = request.additional_args
        timeout = request.timeout
        
        if not target:
            logger.warning("Nuclei stream called without target parameter")
            raise HTTPException(status_code=400, detail="Target parameter is required")
        
        cmd = ["nuclei", "-target", target]
        
        if templates:
            cmd.extend(["-t", templates])
        
        if additional_args:
            cmd.extend(split_args(additional_args))
        
        async def generate_output():
            # 创建异步子进程
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # 用于跟踪命令执行状态
            status = {
                "command": ' '.join(cmd),
                "status": "running",
                "return_code": None,
                "timed_out": False
            }
            
            # 发送初始状态
            yield json.dumps(status) + "\n"
            
            # 设置超时
            cmd_timeout = timeout or COMMAND_TIMEOUT
            
            # 读取输出的协程
            async def read_stream(stream, stream_name):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    try:
                        line_str = line.decode('utf-8')
                        output = {
                            "stream": stream_name,
                            "data": line_str.rstrip()
                        }
                        yield json.dumps(output) + "\n"
                    except Exception as e:
                        logger.error(f"Error decoding output: {str(e)}")
            
            # 创建读取任务
            stdout_task = asyncio.create_task(read_stream(process.stdout, "stdout"))
            stderr_task = asyncio.create_task(read_stream(process.stderr, "stderr"))
            
            try:
                # 等待进程完成或超时
                try:
                    return_code = await asyncio.wait_for(process.wait(), timeout=cmd_timeout)
                    status["status"] = "completed"
                    status["return_code"] = return_code
                    status["success"] = return_code == 0
                except asyncio.TimeoutError:
                    # 进程超时
                    status["status"] = "timeout"
                    status["timed_out"] = True
                    status["success"] = False
                    # 尝试终止进程
                    try:
                        process.terminate()
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        # 强制终止
                        process.kill()
                
                # 等待输出读取完成
                async for line in stdout_task:
                    yield line
                async for line in stderr_task:
                    yield line
                
                # 发送最终状态
                yield json.dumps(status) + "\n"
                
            except Exception as e:
                logger.error(f"Error in streaming: {str(e)}")
                error_status = {
                    "status": "error",
                    "error": str(e),
                    "success": False
                }
                yield json.dumps(error_status) + "\n"
        
        return StreamingResponse(
            generate_output(),
            media_type="application/x-ndjson"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in nuclei stream endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

# 添加导入asyncio
import asyncio

# 添加导入time模块
import time

# 启动终端窗口函数
def open_terminal_window():
    """打开一个新的终端窗口用于显示命令执行情况"""
    global terminal_process
    
    if not TERMINAL_WINDOW_ENABLED:
        return None
    
    try:
        # 创建命令日志文件
        command_log_path = os.path.join(os.getcwd(), TERMINAL_COMMAND_FILE)
        with open(command_log_path, 'w') as f:
            current_time = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"# MCP 命令执行日志 - 启动时间: {current_time}\n\n")
        
        # 检测操作系统
        system = platform.system().lower()
        
        if "linux" in system:
            # 在Linux上创建一个监视命令日志文件的终端
            terminal_cmd = None
            
            # 尝试不同的终端模拟器
            terminal_options = [
                # 使用tail -f监视日志文件
                ["gnome-terminal", "--title", TERMINAL_WINDOW_TITLE, "--", "tail", "-f", command_log_path],
                ["konsole", "--title", TERMINAL_WINDOW_TITLE, "-e", "tail -f " + command_log_path],
                ["xfce4-terminal", "--title", TERMINAL_WINDOW_TITLE, "-e", "tail -f " + command_log_path],
                ["xterm", "-T", TERMINAL_WINDOW_TITLE, "-e", "tail -f " + command_log_path],
                ["x-terminal-emulator", "-e", "tail -f " + command_log_path],
                ["qterminal", "-e", "tail -f " + command_log_path]
            ]
            
            for cmd in terminal_options:
                try:
                    terminal_process = subprocess.Popen(cmd)
                    logger.info(f"已打开终端窗口: {cmd[0]}")
                    return terminal_process
                except Exception as e:
                    logger.debug(f"尝试打开 {cmd[0]} 失败: {str(e)}")
                    continue
            
            # 如果所有终端都失败，尝试使用系统默认终端
            try:
                cmd = ["bash", "-c", f"$TERMINAL -e 'tail -f {command_log_path}' || x-terminal-emulator -e 'tail -f {command_log_path}'"]
                terminal_process = subprocess.Popen(cmd, shell=True)
                logger.info("已打开系统默认终端窗口")
                return terminal_process
            except Exception as e:
                logger.error(f"无法打开终端窗口: {str(e)}")
        
        elif "darwin" in system:  # macOS
            # 在macOS上使用Terminal.app打开tail命令
            script = f"tell application \"Terminal\" to do script \"tail -f {command_log_path}\""
            cmd = ["osascript", "-e", script]
            terminal_process = subprocess.Popen(cmd)
            logger.info("已打开macOS终端窗口")
            return terminal_process
            
        elif "windows" in system:
            # 在Windows上使用PowerShell的Get-Content -Wait命令（类似tail -f）
            cmd = ["start", "cmd.exe", "/k", 
                  f"title {TERMINAL_WINDOW_TITLE} && powershell -Command \"Get-Content -Path '{command_log_path}' -Wait\""]
            terminal_process = subprocess.Popen(cmd, shell=True)
            logger.info("已打开Windows命令提示符窗口")
            return terminal_process
            
        else:
            logger.warning(f"不支持的操作系统: {system}")
            return None
            
    except Exception as e:
        logger.error(f"打开终端窗口时出错: {str(e)}")
        return None

# 启动应用
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kali API Server")
    parser.add_argument("--port", type=int, default=API_PORT, help="Port to run the server on")
    parser.add_argument("--debug", action="store_true", default=DEBUG_MODE, help="Run in debug mode")
    parser.add_argument("--no-terminal", action="store_true", help="Disable terminal window")
    args = parser.parse_args()
    
    # 根据命令行参数设置是否启用终端窗口
    if args.no_terminal:
        TERMINAL_WINDOW_ENABLED = False
    
    logger.info(f"Starting Kali API Server on port {args.port}")
    # 获取本机实际IP地址（非回环地址）
    def get_local_ip():
        try:
            # 创建一个临时socket连接到外部地址，这样可以确定使用哪个网络接口
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # 不需要真正连接到8.8.8.8，只是用来确定路由
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            logger.warning(f"无法获取本机IP地址: {e}")
            # 回退到传统方法
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
    
    local_ip = get_local_ip()
    logger.info(f"Server will be accessible at http://127.0.0.1:{args.port} and http://{local_ip}:{args.port}")
    
    # 打开终端窗口
    if TERMINAL_WINDOW_ENABLED:
        logger.info("正在打开命令执行终端窗口...")
        terminal_proc = open_terminal_window()
        if terminal_proc:
            logger.info(f"终端窗口已打开，进程ID: {terminal_proc.pid}")
        else:
            logger.warning("无法打开终端窗口，将在当前控制台显示命令输出")
    
    # 启动服务器
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="debug" if args.debug else "info")
