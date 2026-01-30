#!/usr/bin/env python3
import requests
import sys
import urllib.parse

def test_path_traversal(server_url):
    """测试路径遍历漏洞防护"""
    
    test_cases = [
        # (路径, 期望结果, 描述)
        ("/index.html", "200", "正常访问"),
        ("/test.txt", "200", "正常文件"),
        ("/../root/index.html", "403", "路径遍历1 - 相对路径"),
        ("/../root/../root/index.html", "403", "路径遍历2 - 多层相对路径"),
        ("/././index.html", "200", "当前目录 - 应允许"),
        ("/../../../etc/passwd", "403", "经典路径遍历 - 应拦截"),
        ("/%2e%2e/%2e%2e/etc/passwd", "403", "URL编码绕过 - 应拦截"),
        ("/..\\..\\..\\windows\\system32", "403", "Windows风格 - 应拦截"),
        ("/root/../../etc/passwd", "403", "混合路径 - 应拦截"),
        ("/symlink_to_outside", "403", "符号链接攻击 - 应拦截"),
        # 新增测试用例
        ("/etc/passwd", "403", "直接访问系统文件 - 应拦截"),
        ("/bin/ls", "403", "直接访问系统二进制文件 - 应拦截"),
        ("/../../../../etc/passwd", "403", "多层路径遍历 - 应拦截"),
        ("/%252e%252e/%252e%252e/etc/passwd", "403", "双重URL编码 - 应拦截"),
        ("//etc//passwd", "403", "多余斜杠 - 应拦截"),
        ("/\.\./\.\./etc/passwd", "403", "转义字符 - 应拦截"),
        ("/judge.html", "200", "白名单文件 - 应允许"),
        ("/welcome.html", "200", "白名单文件 - 应允许"),
        ("/unknown.exe", "403", "非白名单扩展名 - 应拦截"),
        ("/config.ini", "403", "非白名单扩展名 - 应拦截"),
    ]
    
    print("=== 路径遍历漏洞防护测试 ===\n")
    print(f"服务器地址: {server_url}")
    print("=" * 80)
    
    passed = 0
    failed = 0
    errors = 0
    
    for path, expected, description in test_cases:
        try:
            # 对于 Windows 风格的反斜杠，需要正确编码
            encoded_path = path.replace('\\', '%5C') if '\\' in path else path
            response = requests.get(f"{server_url}{encoded_path}", timeout=5)
            actual = str(response.status_code)
            
            if actual == expected:
                status = "✓ PASS"
                passed += 1
            else:
                status = "✗ FAIL"
                failed += 1
            
            print(f"{status:10} | {description:40}")
            print(f"          路径: {path}")
            print(f"          编码后: {encoded_path}")
            print(f"          期望: {expected}, 实际: {actual}")
            if response.status_code == 200:
                print(f"          内容长度: {len(response.text)} chars")
            elif response.status_code == 403:
                print(f"          拦截原因: 路径遍历防护生效")
            print()
            
        except requests.exceptions.RequestException as e:
            print(f"✗ ERROR  | {description:40}")
            print(f"          路径: {path}")
            print(f"          错误: {e}")
            print()
            errors += 1
        except Exception as e:
            print(f"✗ ERROR  | {description:40}")
            print(f"          路径: {path}")
            print(f"          异常: {type(e).__name__}: {e}")
            print()
            errors += 1
    
    print("=" * 80)
    print(f"测试结果: 通过 {passed}, 失败 {failed}, 错误 {errors}, 总计 {passed + failed + errors}")
    print()
    
    if failed == 0 and errors == 0:
        print("✓ 所有测试用例通过！路径遍历防护完全生效。")
        return True
    elif failed > 0:
        print(f"✗ 有 {failed} 个测试用例失败，需要进一步检查。")
        return False
    else:
        print(f"⚠ 有 {errors} 个测试用例出现连接错误，可能服务器处理异常。")
        return False

def test_normal_access(server_url):
    """测试正常文件访问"""
    print("\n=== 正常文件访问测试 ===")
    print("测试白名单中的文件是否可正常访问")
    print("-" * 60)
    
    allowed_files = [
        "/index.html",
        "/test.txt",
        "/judge.html",
        "/log.html",
        "/register.html",
        "/picture.html",
        "/video.html",
        "/fans.html",
        "/welcome.html",
    ]
    
    for file_path in allowed_files:
        try:
            response = requests.get(f"{server_url}{file_path}", timeout=5)
            print(f"文件: {file_path:20} 状态: {response.status_code:3}", end=" ")
            if response.status_code == 200:
                print("✓")
            else:
                print(f"✗ (期望 200)")
        except Exception as e:
            print(f"文件: {file_path:20} 错误: {e}")

def test_security_headers(server_url):
    """测试安全头信息"""
    print("\n=== 安全头信息测试 ===")
    print("检查服务器返回的安全相关HTTP头")
    print("-" * 60)
    
    try:
        response = requests.get(f"{server_url}/index.html", timeout=5)
        headers = response.headers
        
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': None,  # 可选
        }
        
        for header, expected_value in security_headers.items():
            if header in headers:
                value = headers[header]
                if expected_value and value != expected_value:
                    print(f"✗ {header}: {value} (期望: {expected_value})")
                else:
                    print(f"✓ {header}: {value}")
            else:
                print(f"⚠ {header}: 未设置")
                
    except Exception as e:
        print(f"测试失败: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方法: python3 test_path_traversal.py <服务器URL>")
        print("示例: python3 test_path_traversal.py http://localhost:9006")
        sys.exit(1)
    
    server_url = sys.argv[1]
    
    # 运行主要测试
    print("正在测试路径遍历漏洞防护...")
    success = test_path_traversal(server_url)
    
    if success:
        # 运行额外测试
        test_normal_access(server_url)
        test_security_headers(server_url)
    
    # 给出修复建议
    print("\n=== 修复建议 ===")
    print("如果测试失败，请检查：")
    print("1. 服务器是否已应用最新的路径遍历防护代码")
    print("2. doc_root 设置是否正确")
    print("3. 白名单文件配置是否完整")
    print("4. URL 解码是否正确处理")
    
    sys.exit(0 if success else 1)