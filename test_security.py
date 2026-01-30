#!/usr/bin/env python3
import requests
import sys
import time

def test_case(url, path, expected_status, description):
    """测试单个用例"""
    try:
        print(f"测试: {description}")
        print(f"  路径: {path}")
        
        response = requests.get(url + path, timeout=10)
        actual_status = response.status_code
        
        if actual_status == expected_status:
            print(f"  ✓ 通过: 期望 {expected_status}, 实际 {actual_status}")
            if actual_status == 200:
                print(f"    内容长度: {len(response.text)} 字节")
            return True
        else:
            print(f"  ✗ 失败: 期望 {expected_status}, 实际 {actual_status}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"  ✗ 错误: {e}")
        return False
    except Exception as e:
        print(f"  ✗ 异常: {type(e).__name__}: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("使用方法: python3 test_security.py <服务器URL>")
        print("示例: python3 test_security.py http://localhost:9006")
        sys.exit(1)
    
    server_url = sys.argv[1]
    print(f"=== 测试服务器: {server_url} ===\n")
    
    test_cases = [
        # 正常访问测试
        ("/index.html", 200, "正常访问首页"),
        ("/judge.html", 200, "正常访问 judge.html"),
        ("/welcome.html", 200, "正常访问 welcome.html"),
        ("/test.txt", 200, "正常访问文本文件"),
        
        # 路径遍历攻击测试
        ("/../root/index.html", 403, "相对路径遍历"),
        ("/../../../etc/passwd", 403, "经典路径遍历"),
        ("/%2e%2e/%2e%2e/etc/passwd", 403, "URL编码绕过"),
        ("/..\\..\\..\\windows\\system32", 403, "Windows风格路径"),
        ("/root/../../etc/passwd", 403, "混合路径遍历"),
        
        # 符号链接测试
        ("/symlink_test.txt", 403, "符号链接攻击防护"),
        
        # 白名单外文件测试
        ("/unknown.exe", 403, "非白名单扩展名"),
        ("/config.ini", 403, "非白名单扩展名"),
        
        # 特殊字符测试
        ("//etc//passwd", 403, "多余斜杠"),
        ("/./././etc/passwd", 403, "当前目录混淆"),
    ]
    
    passed = 0
    failed = 0
    
    print("=== 开始测试 ===\n")
    
    for path, expected, description in test_cases:
        if test_case(server_url, path, expected, description):
            passed += 1
        else:
            failed += 1
        print()
    
    print("=== 测试结果 ===")
    print(f"通过: {passed}")
    print(f"失败: {failed}")
    print(f"总计: {passed + failed}")
    
    if failed == 0:
        print("\n✓ 所有测试通过！路径遍历防护完全生效。")
        return True
    else:
        print("\n✗ 部分测试失败，需要检查服务器实现。")
        return False

if __name__ == "__main__":
    # 给服务器一点启动时间
    time.sleep(2)
    success = main()
    sys.exit(0 if success else 1)