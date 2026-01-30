#!/usr/bin/env python3
import requests
import sys
import time

def test_post_security(server_url):
    """测试POST请求的安全性"""
    
    print("=== POST请求安全性测试 ===\n")
    
    test_cases = [
        # (描述, 用户名, 密码, 期望状态码)
        ("正常登录请求", "testuser", "testpass123", 200),
        ("XSS攻击 - script标签", "<script>alert(1)</script>", "password", 400),
        ("XSS攻击 - javascript协议", "test", "javascript:alert(1)", 400),
        ("XSS攻击 - onload事件", "test", "test'onload='alert(1)", 400),
        ("超长用户名", "a" * 150, "test", 400),  # 超过MAX_USERNAME_LEN
        ("超长密码", "test", "a" * 150, 400),  # 超过MAX_PASSWORD_LEN
        ("SQL注入尝试", "admin' OR '1'='1", "password", 400),
        ("HTML实体编码攻击", "&#x3C;script&#x3E;", "test", 400),
    ]
    
    passed = 0
    failed = 0
    
    for description, username, password, expected in test_cases:
        try:
            print(f"测试: {description}")
            print(f"  用户名: {username[:50]}..." if len(username) > 50 else f"  用户名: {username}")
            print(f"  密码: {password[:50]}..." if len(password) > 50 else f"  密码: {password}")
            
            # 发送POST请求到登录页面
            response = requests.post(
                f"{server_url}/2",
                data={"user": username, "passwd": password},
                timeout=10
            )
            
            actual = response.status_code
            
            if actual == expected:
                print(f"  ✓ 通过: 期望 {expected}, 实际 {actual}")
                passed += 1
            else:
                print(f"  ✗ 失败: 期望 {expected}, 实际 {actual}")
                failed += 1
                
        except requests.exceptions.RequestException as e:
            print(f"  ✗ 错误: {e}")
            failed += 1
        
        print()
    
    # 测试超大POST请求
    print("测试: 超大POST请求体")
    try:
        # 创建超过1MB的数据
        huge_data = "user=test&passwd=" + "x" * (1024 * 1024 + 100)
        response = requests.post(
            f"{server_url}/2",
            data=huge_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=15
        )
        actual = response.status_code
        
        # 期望返回400（BAD_REQUEST）因为超过大小限制
        if actual == 400:
            print(f"  ✓ 通过: 成功拦截超大POST请求")
            passed += 1
        else:
            print(f"  ✗ 失败: 期望400, 实际{actual}")
            failed += 1
            
    except Exception as e:
        print(f"  ✗ 错误: {e}")
        failed += 1
    
    print(f"\n=== 测试结果 ===")
    print(f"通过: {passed}")
    print(f"失败: {failed}")
    print(f"总计: {passed + failed}")
    
    return failed == 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方法: python3 test_security_post.py <服务器URL>")
        print("示例: python3 test_security_post.py http://localhost:9006")
        sys.exit(1)
    
    server_url = sys.argv[1]
    
    # 等待服务器启动
    time.sleep(2)
    
    success = test_post_security(server_url)
    
    if success:
        print("\n✓ POST请求安全性防护生效！")
    else:
        print("\n✗ POST请求安全性防护存在漏洞")
    
    sys.exit(0 if success else 1)