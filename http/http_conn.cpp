#include "http_conn.h"
#include<cctype>
#include<cstring>
#include <mysql/mysql.h>
#include <fstream>

// 静态成员变量定义（必须在 .cpp 中）


// 构造函数实现
http_conn::http_conn()
    : m_sockfd(-1), m_state(0), m_read_idx(0), m_checked_idx(0),
      m_start_line(0), m_write_idx(0), m_check_state(CHECK_STATE_REQUESTLINE),
      m_method(GET), m_content_length(0), m_linger(false),
      m_iv_count(0), bytes_to_send(0), bytes_have_send(0), cgi(0),
      timer_flag(0), improv(0), m_TRIGMode(0), m_close_log(0)
{
    // 数组已在头文件中用 = {0} 初始化，此处可省略 memset
    // 但为保险起见，也可保留：
    memset(m_read_buf, 0, READ_BUFFER_SIZE);
    memset(m_write_buf, 0, WRITE_BUFFER_SIZE);
    memset(m_real_file, 0, FILENAME_LEN);

    std::cout << "DEBUG: http_conn constructor called at address: " << this << std::endl;
}

// 析构函数实现
http_conn::~http_conn() {
    unmap();
}
//定义http响应的一些状态信息
const char *ok_200_title = "OK";
const char *error_400_title = "Bad Request";
const char *error_400_form = "Your request has bad syntax or is inherently impossible to staisfy.\n";
const char *error_403_title = "Forbidden";
const char *error_403_form = "You do not have permission to get file form this server.\n";
const char *error_404_title = "Not Found";
const char *error_404_form = "The requested file was not found on this server.\n";
const char *error_500_title = "Internal Error";
const char *error_500_form = "There was an unusual problem serving the request file.\n";

locker m_lock;
map<string, string> users;

void http_conn::initmysql_result(connection_pool *connPool)
{
    //先从连接池中取一个连接
    MYSQL *mysql = NULL;
    connectionRAII mysqlcon(&mysql, connPool);

    //在user表中检索username，passwd数据，浏览器端输入
    if (mysql_query(mysql, "SELECT username,passwd FROM user"))
    {
        LOG_ERROR("SELECT error:%s\n", mysql_error(mysql));
    }

    //从表中检索完整的结果集
    MYSQL_RES *result = mysql_store_result(mysql);

    //返回结果集中的列数
    int num_fields = mysql_num_fields(result);

    //返回所有字段结构的数组
    MYSQL_FIELD *fields = mysql_fetch_fields(result);

    //从结果集中获取下一行，将对应的用户名和密码，存入map中
    while (MYSQL_ROW row = mysql_fetch_row(result))
    {
        string temp1(row[0]);
        string temp2(row[1]);
        users[temp1] = temp2;
    }
}

//对文件描述符设置非阻塞
int setnonblocking(int fd)
{
    int old_option = fcntl(fd, F_GETFL);
    int new_option = old_option | O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}
int http_conn::ssl_read(char* buf, int len) {
    if (!m_ssl) return -1;
    return SSL_read(m_ssl, buf, len);
}

int http_conn::ssl_write(const char* buf, int len) {
    if (!m_ssl) return -1;
    return SSL_write(m_ssl, buf, len);
}

//将内核事件表注册读事件，ET模式，选择开启EPOLLONESHOT
void addfd(int epollfd, int fd, bool one_shot, int TRIGMode)
{
        std::cout << "DEBUG: addfd() called - epollfd=" << epollfd << ", fd=" << fd << std::endl;
    
    epoll_event event;
    event.data.fd = fd;

    if (1 == TRIGMode)
        event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    else
        event.events = EPOLLIN | EPOLLRDHUP;

    if (one_shot)
        event.events |= EPOLLONESHOT;
    
    std::cout << "DEBUG: Calling epoll_ctl()" << std::endl;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
    setnonblocking(fd);
}

//从内核时间表删除描述符
void removefd(int epollfd, int fd)
{
    epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, 0);
    close(fd);
}

//将事件重置为EPOLLONESHOT
void modfd(int epollfd, int fd, int ev, int TRIGMode)
{
    epoll_event event;
    event.data.fd = fd;

    if (1 == TRIGMode)
        event.events = ev | EPOLLET | EPOLLONESHOT | EPOLLRDHUP;
    else
        event.events = ev | EPOLLONESHOT | EPOLLRDHUP;

    epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);
}

int http_conn::m_user_count = 0;
int http_conn::m_epollfd = -1;

//关闭连接，关闭一个连接，客户总量减一
void http_conn::close_conn(bool real_close) {
    if (real_close && (m_sockfd != -1)) {
        printf("close %d\n", m_sockfd);

        // 释放 SSL
        if (m_ssl) {
            SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
            m_ssl = nullptr;
            m_is_https = false;
        }

        removefd(m_epollfd, m_sockfd);
        m_sockfd = -1;
        m_user_count--;
    }
}

//初始化连接,外部调用初始化套接字地址
void http_conn::init(int sockfd, const sockaddr_in &addr, char *root, int TRIGMode,
                     int close_log, string user, string passwd, string sqlname)
{
        std::cout << "DEBUG: http_conn::init() - Starting init for fd=" << sockfd << std::endl;
    std::cout << "DEBUG: m_epollfd=" << m_epollfd << std::endl;
    std::cout << "DEBUG: root pointer=" << (void*)root << std::endl;
    
    m_sockfd = sockfd;
    m_address = addr;
    m_TRIGMode = TRIGMode;
    
    std::cout << "DEBUG: Before addfd()" << std::endl;
    addfd(m_epollfd, sockfd, true, m_TRIGMode);
    std::cout << "DEBUG: After addfd()" << std::endl;
    
    m_user_count++;

    doc_root = root;
    m_close_log = close_log;

    strcpy(sql_user, user.c_str());
    strcpy(sql_passwd, passwd.c_str());
    strcpy(sql_name, sqlname.c_str());

    std::cout << "DEBUG: Before calling internal init()" << std::endl;
    init();
    std::cout << "DEBUG: After init()" << std::endl;
        m_ssl_handshake_done = false;
}

//初始化新接受的连接
//check_state默认为分析请求行状态
void http_conn::init()
{
    mysql = NULL;
    bytes_to_send = 0;
    bytes_have_send = 0;
    m_check_state = CHECK_STATE_REQUESTLINE;
    m_linger = false;
    m_method = GET;
    m_url = 0;
    m_version = 0;
    m_content_length = 0;
    m_host = 0;
    m_start_line = 0;
    m_checked_idx = 0;
    m_read_idx = 0;
    m_write_idx = 0;
    cgi = 0;
    m_state = 0;
    timer_flag = 0;
    improv = 0;

    memset(m_read_buf, '\0', READ_BUFFER_SIZE);
    memset(m_write_buf, '\0', WRITE_BUFFER_SIZE);
    memset(m_real_file, '\0', FILENAME_LEN);
}

//从状态机，用于分析出一行内容
//返回值为行的读取状态，有LINE_OK,LINE_BAD,LINE_OPEN
http_conn::LINE_STATUS http_conn::parse_line()
{
    char temp;
    for (; m_checked_idx < m_read_idx; ++m_checked_idx)
    {
        temp = m_read_buf[m_checked_idx];
        if (temp == '\r')
        {
            if ((m_checked_idx + 1) == m_read_idx)
                return LINE_OPEN;
            else if (m_read_buf[m_checked_idx + 1] == '\n')
            {
                m_read_buf[m_checked_idx++] = '\0';
                m_read_buf[m_checked_idx++] = '\0';
                return LINE_OK;
            }
            return LINE_BAD;
        }
        else if (temp == '\n')
        {
            if (m_checked_idx > 1 && m_read_buf[m_checked_idx - 1] == '\r')
            {
                m_read_buf[m_checked_idx - 1] = '\0';
                m_read_buf[m_checked_idx++] = '\0';
                return LINE_OK;
            }
            return LINE_BAD;
        }
    }
    return LINE_OPEN;
}

bool http_conn::read_once() {
    if (m_read_idx >= READ_BUFFER_SIZE) {
        return false;
    }

    // ========== 第一步：处理 SSL 握手 ==========
    if (m_is_https && !m_ssl_handshake_done) {
        int ret = SSL_accept(m_ssl);
        if (ret == 1) {
            // 握手成功！立即返回，等待下一次可读事件来读取 HTTP 请求
            m_ssl_handshake_done = true;
            LOG_INFO("SSL handshake successful for fd=%d", m_sockfd);
            // 👇 关键：握手成功后不要立即读数据，返回 true 等待新事件
            return true;
        } else {
            int err = SSL_get_error(m_ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
                return true;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                modfd(m_epollfd, m_sockfd, EPOLLOUT, m_TRIGMode);
                return true;
            } else {
                LOG_ERROR("SSL handshake failed for fd=%d, error=%d", m_sockfd, err);
                ERR_print_errors_fp(stderr);
                return false;
            }
        }
    }

    // ========== 第二步：读取应用数据（HTTP请求）==========
    // 注意：只有握手完成（或非 HTTPS）才执行到这里
    int bytes_read = 0;
    if (m_is_https) {
        bytes_read = SSL_read(m_ssl, m_read_buf + m_read_idx, READ_BUFFER_SIZE - m_read_idx);
    } else {
        if (m_TRIGMode == 0) {
            bytes_read = recv(m_sockfd, m_read_buf + m_read_idx, READ_BUFFER_SIZE - m_read_idx, 0);
        } else {
            bytes_read = recv(m_sockfd, m_read_buf + m_read_idx, READ_BUFFER_SIZE - m_read_idx, MSG_WAITALL);
        }
    }

    if (bytes_read > 0) {
        m_read_idx += bytes_read;
        return true;
    } else if (bytes_read == 0) {
        // 对端正常关闭
        return false;
    } else {
        // SSL_read 或 recv 出错
        int ssl_err = 0;
        if (m_is_https) {
            ssl_err = SSL_get_error(m_ssl, bytes_read);
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                // 非致命错误，等待下一次事件
                return true;
            }
        }
        // 其他错误（包括普通 socket 的 EAGAIN）
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;
        }
        return false;
    }
}


//解析http请求的一个头部信息
http_conn::HTTP_CODE http_conn::parse_headers(char *text)
{    if (text[0] == '\0')
    {
        if (m_content_length != 0)
        {
            // ============ 新增：检查POST请求体大小 ============
            if (m_method == POST && is_post_too_large()) {
                std::cout << "SECURITY: POST request too large: " << m_content_length 
                          << " bytes (max: " << MAX_POST_SIZE << ")" << std::endl;
                LOG_ERROR("POST request too large: %d bytes", m_content_length);
                return BAD_REQUEST;
            }
            // =================================================
            
            m_check_state = CHECK_STATE_CONTENT;
            return NO_REQUEST;
        }
        return GET_REQUEST;
    }
    else if (strncasecmp(text, "Connection:", 11) == 0)
    {
        text += 11;
        text += strspn(text, " \t");
        if (strcasecmp(text, "keep-alive") == 0)
        {
            m_linger = true;
        }
    }
       else if (strncasecmp(text, "Content-length:", 15) == 0)
    {
        text += 15;
        text += strspn(text, " \t");
        m_content_length = atol(text);
        
        // ============ 新增：立即检查长度 ============
        if (m_method == POST && is_post_too_large()) {
            std::cout << "SECURITY: POST content-length too large: " << m_content_length 
                      << " bytes (max: " << MAX_POST_SIZE << ")" << std::endl;
            LOG_ERROR("POST content-length too large: %d bytes", m_content_length);
            return BAD_REQUEST;
        }
        // ===========================================
    }
    else if (strncasecmp(text, "Host:", 5) == 0)
    {
        text += 5;
        text += strspn(text, " \t");
        m_host = text;
    }
    else
    {
        LOG_INFO("oop!unknow header: %s", text);
    }
    return NO_REQUEST;
}

//判断http请求是否被完整读入
http_conn::HTTP_CODE http_conn::parse_content(char *text)
{
    if (m_read_idx >= (m_content_length + m_checked_idx))
    {
        text[m_content_length] = '\0';
        //POST请求中最后为输入的用户名和密码
        m_string = text;
        return GET_REQUEST;
    }
    return NO_REQUEST;
}

http_conn::HTTP_CODE http_conn::process_read()
{
    LINE_STATUS line_status = LINE_OK;
    HTTP_CODE ret = NO_REQUEST;
    char *text = 0;

    while ((m_check_state == CHECK_STATE_CONTENT && line_status == LINE_OK) || ((line_status = parse_line()) == LINE_OK))
    {
        text = get_line();
        m_start_line = m_checked_idx;
        LOG_INFO("%s", text);
        switch (m_check_state)
        {
        case CHECK_STATE_REQUESTLINE:
        {
            ret = parse_request_line(text);
            if (ret == BAD_REQUEST)
                return BAD_REQUEST;
            break;
        }
        case CHECK_STATE_HEADER:
        {
            ret = parse_headers(text);
            if (ret == BAD_REQUEST)
                return BAD_REQUEST;
            else if (ret == GET_REQUEST)
            {
                return do_request();
            }
            break;
        }
        case CHECK_STATE_CONTENT:
        {
            ret = parse_content(text);
            if (ret == GET_REQUEST)
                return do_request();
            line_status = LINE_OPEN;
            break;
        }
        default:
            return INTERNAL_ERROR;
        }
    }
    return NO_REQUEST;
}
// 解析请求行：GET /index.html HTTP/1.1
http_conn::HTTP_CODE http_conn::parse_request_line(char *text)
{
    // 请求行格式：METHOD URL VERSION
    char *method = text;
    char *url = strpbrk(method, " \t");
    if (!url) {
        return BAD_REQUEST;
    }
    *url++ = '\0';
    url += strspn(url, " \t");

    char *version = strpbrk(url, " \t");
    if (!version) {
        return BAD_REQUEST;
    }
    *version++ = '\0';
    version += strspn(version, " \t");

    // 只支持 GET 和 POST
    if (strcasecmp(method, "GET") == 0) {
        m_method = GET;
    } else if (strcasecmp(method, "POST") == 0) {
        m_method = POST;
        cgi = 1; // 标记为 CGI 请求
    } else {
        return BAD_REQUEST;
    }

    // 检查 HTTP 版本（只支持 HTTP/1.1）
    if (strcasecmp(version, "HTTP/1.1") != 0) {
        return BAD_REQUEST;
    }

    // 处理 URL
    if (url[0] == '/') {
        m_url = url;
    } else {
        return BAD_REQUEST;
    }

    // 跳过主机部分（Host: 在头部处理）
    m_check_state = CHECK_STATE_HEADER;
    return NO_REQUEST;
}

http_conn::HTTP_CODE http_conn::do_request()
{
    std::cout << "\n=== DEBUG: do_request() called ===" << std::endl;
    std::cout << "DEBUG: Request URL: " << (m_url ? m_url : "null") << std::endl;
    std::cout << "DEBUG: Document root: " << (doc_root ? doc_root : "null") << std::endl;

    if (!doc_root || !m_url) {
        std::cout << "ERROR: doc_root or m_url is null!" << std::endl;
        return INTERNAL_ERROR;
    }
    
    // ============ 第一层防护：URL 检查 ============
    std::cout << "DEBUG: Checking URL for path traversal..." << std::endl;
    
    auto url_decode = [](const char* src, char* dst, size_t dst_size) -> bool {
        if (!src || !dst || dst_size == 0) return false;
        size_t i = 0, j = 0;
        while (src[i] && j < dst_size - 1) {
            if (src[i] == '%' && src[i+1] && src[i+2]) {
                char hex[3] = {src[i+1], src[i+2], '\0'};
                char decoded = (char)strtol(hex, NULL, 16);
                dst[j++] = decoded;
                i += 3;
            } else if (src[i] == '+') {
                dst[j++] = ' ';
                i++;
            } else {
                dst[j++] = src[i++];
            }
        }
        dst[j] = '\0';
        return true;
    };
    
    char decoded_url[1024] = {0};
    url_decode(m_url, decoded_url, sizeof(decoded_url));
    
    std::cout << "DEBUG: Original URL: " << m_url << std::endl;
    std::cout << "DEBUG: Decoded URL: " << decoded_url << std::endl;
    
    bool has_traversal = false;
    const char* check_url = decoded_url[0] ? decoded_url : m_url;
    
    if (strstr(check_url, "../") || 
        strstr(check_url, "..\\") ||
        strstr(check_url, "/../") ||
        strstr(check_url, "/..\\") ||
        strstr(check_url, "\\..\\") ||
        strstr(check_url, "\\../") ||
        strstr(m_url, "%2e%2e") ||  
        strstr(m_url, "%252e%252e") ||  
        strstr(check_url, "//") ||  
        strstr(check_url, "\\\\"))  
    {
        has_traversal = true;
        std::cout << "SECURITY: Path traversal detected in URL: " << check_url << std::endl;
    }
    
    if (check_url[0] == '/' && check_url[1] && check_url[1] != '/') {
        const char* sys_dirs[] = {"/etc/", "/bin/", "/usr/", "/var/", "/tmp/",
                                  "/home/", "/root/", "/boot/", "/dev/", "/proc/", "/sys/"};
        for (const char* dir : sys_dirs) {
            if (strstr(check_url, dir)) {
                has_traversal = true;
                std::cout << "SECURITY: Attempt to access system directory: " << check_url << std::endl;
                break;
            }
        }
    }
    
    if (has_traversal) {
        LOG_ERROR("Path traversal attempt blocked: original=%s, decoded=%s", m_url, decoded_url);
        return FORBIDDEN_REQUEST;
    }
    
    // ============ 初始化 m_real_file ============
    memset(m_real_file, '\0', FILENAME_LEN);
    strncpy(m_real_file, doc_root, FILENAME_LEN - 1);
    
    const char *p = strrchr(check_url, '/');
    if (!p) {
        std::cout << "ERROR: No '/' found in URL: " << check_url << std::endl;
        return BAD_REQUEST;
    }
    
    char next_char = *(p + 1);
    bool is_allowed_file = false;

    // ============ 处理CGI请求（登录/注册） ============
    if (cgi == 1 && (next_char == '2' || next_char == '3')) {
        std::cout << "DEBUG: Processing CGI request" << std::endl;
        
        if (!mysql) {
            std::cout << "ERROR: MySQL connection is null!" << std::endl;
            snprintf(m_real_file, FILENAME_LEN, "%s/%s", doc_root,
                     (next_char == '3') ? "registerError.html" : "logError.html");
            is_allowed_file = true;
        } else {
            char name[MAX_USERNAME_LEN] = {0};
            char password[MAX_PASSWORD_LEN] = {0};
            
            if (m_string) {
                std::cout << "DEBUG: Raw POST data: [" << m_string << "]" << std::endl;

                if (has_xss_keywords(m_string)) {
                    std::cout << "SECURITY: XSS keywords detected in POST data" << std::endl;
                    LOG_ERROR("XSS attack attempt detected in POST data");
                    return BAD_REQUEST;
                }

                char* user_start = strstr(m_string, "user=");
                if (user_start) {
                    user_start += 5;
                    char* user_end = strchr(user_start, '&');
                    int len = user_end ? (user_end - user_start) : strlen(user_start);
                    if (len > 0 && len < MAX_USERNAME_LEN) {
                        strncpy(name, user_start, len);
                        name[len] = '\0';
                    }
                }

                char* pass_start = strstr(m_string, "passwd=");
                if (pass_start) {
                    pass_start += 7;
                    char* pass_end = strchr(pass_start, '&');
                    int len = pass_end ? (pass_end - pass_start) : strlen(pass_start);
                    if (len > 0 && len < MAX_PASSWORD_LEN) {
                        strncpy(password, pass_start, len);
                        password[len] = '\0';
                    }
                }

                auto trim_crlf = [](char* s) {
                    int len = strlen(s);
                    while (len > 0 && (s[len-1] == '\r' || s[len-1] == '\n' || s[len-1] == ' ')) {
                        s[--len] = '\0';
                    }
                };
                trim_crlf(name);
                trim_crlf(password);
                
                std::cout << "DEBUG: Before sanitization - name='" << name 
                          << "', password='" << password << "'" << std::endl;
                
                if (!is_input_valid(name, MAX_USERNAME_LEN - 1) || 
                    !is_input_valid(password, MAX_PASSWORD_LEN - 1)) {
                    std::cout << "SECURITY: Invalid input length" << std::endl;
                    LOG_ERROR("Invalid input length detected");
                    snprintf(m_real_file, FILENAME_LEN, "%s/%s", doc_root,
                             (next_char == '3') ? "registerError.html" : "logError.html");
                    is_allowed_file = true;
                }
                else if (has_xss_keywords(name) || has_xss_keywords(password)) {
                    std::cout << "SECURITY: XSS keywords detected in user input" << std::endl;
                    LOG_ERROR("XSS attack attempt: name=%s", name);
                    return BAD_REQUEST;
                }
                else {
                    sanitize_input(name, MAX_USERNAME_LEN);
                    sanitize_input(password, MAX_PASSWORD_LEN);
                    std::cout << "DEBUG: After sanitization - name='" << name 
                              << "', password='" << password << "'" << std::endl;
                }
            }

            std::cout << "DEBUG: Extracted - name='" << name << "', password='" << password << "'" << std::endl;
            
            // 注册（3）
            if (next_char == '3') {
                char sql_insert[256];
                snprintf(sql_insert, sizeof(sql_insert),
                         "INSERT INTO user(username, passwd) VALUES('%s', '%s')",
                         name, password);

                if (users.find(name) == users.end()) {
                    m_lock.lock();
                    int res = mysql_query(mysql, sql_insert);
                    if (!res) {
                        users.insert({name, password});
                    }
                    m_lock.unlock();

                    if (!res) {
                        snprintf(m_real_file, FILENAME_LEN, "%s/welcome.html", doc_root);
                        is_allowed_file = true;
                    } else {
                        snprintf(m_real_file, FILENAME_LEN, "%s/registerError.html", doc_root);
                        is_allowed_file = true;
                    }
                } else {
                    snprintf(m_real_file, FILENAME_LEN, "%s/registerError.html", doc_root);
                    is_allowed_file = true;
                }
            }
            // 登录（2）
            else if (next_char == '2') {
                if (users.find(name) != users.end() && users[name] == password) {
                    snprintf(m_real_file, FILENAME_LEN, "%s/welcome.html", doc_root);
                    is_allowed_file = true;
                } else {
                    snprintf(m_real_file, FILENAME_LEN, "%s/logError.html", doc_root);
                    is_allowed_file = true;
                }
            }
        }

        // ✅ CGI 已处理完毕，跳过后续路径构建
        goto skip_path_building;
    }

    // ============ 第三层防护：安全的路径构建（仅用于非CGI请求） ============
    if (strcmp(check_url, "/") == 0) {
        std::cout << "DEBUG: Root path requested, serving /judge.html" << std::endl;
        snprintf(m_real_file, FILENAME_LEN, "%s/judge.html", doc_root);
        is_allowed_file = true;
    } 
    else {
        const char* filename = p + 1;

        if (next_char == '0') {
            snprintf(m_real_file, FILENAME_LEN, "%s/register.html", doc_root);
            is_allowed_file = true;
        }
        else if (next_char == '1') {
            snprintf(m_real_file, FILENAME_LEN, "%s/log.html", doc_root);
            is_allowed_file = true;
        }
        else if (next_char == '5') {
            snprintf(m_real_file, FILENAME_LEN, "%s/picture.html", doc_root);
            is_allowed_file = true;
        }
        else if (next_char == '6') {
            snprintf(m_real_file, FILENAME_LEN, "%s/video.html", doc_root);
            is_allowed_file = true;
        }
        else if (next_char == '7') {
            snprintf(m_real_file, FILENAME_LEN, "%s/fans.html", doc_root);
            is_allowed_file = true;
        }
        else if (strcmp(filename, "judge.html") == 0 ||
                 strcmp(filename, "welcome.html") == 0 ||
                 strcmp(filename, "registerError.html") == 0 ||
                 strcmp(filename, "logError.html") == 0) {
            snprintf(m_real_file, FILENAME_LEN, "%s/%s", doc_root, filename);
            is_allowed_file = true;
        }
        else {
            const char* allowed_ext[] = {
                ".html", ".htm", ".txt",
                ".jpg", ".jpeg", ".png", ".gif", ".ico",
                ".css", ".js",
                ".mp4", ".avi", ".mov", ".webm",
                ".pdf", ".zip", ".tar", ".gz"
            };
            bool ext_allowed = false;
            size_t fname_len = strlen(filename);
            for (const char* ext : allowed_ext) {
                size_t ext_len = strlen(ext);
                if (fname_len >= ext_len && 
                    strcmp(filename + fname_len - ext_len, ext) == 0) {
                    ext_allowed = true;
                    break;
                }
            }
            if (ext_allowed) {
                snprintf(m_real_file, FILENAME_LEN, "%s/%s", doc_root, filename);
                is_allowed_file = true;
            }
        }
    }

skip_path_building:

    // ============ 第四层防护：realpath 检查 ============
    char resolved_path[FILENAME_LEN] = {0};
    char* real_result = realpath(m_real_file, resolved_path);
    
    if (real_result == NULL) {
        std::cout << "ERROR: Failed to resolve path: " << m_real_file 
                  << ", errno: " << errno << std::endl;
        if (strstr(m_real_file, "../") || strstr(m_real_file, "..\\")) {
            std::cout << "SECURITY: Path traversal in constructed path" << std::endl;
            return FORBIDDEN_REQUEST;
        }
        return NO_RESOURCE;
    }
    
    size_t root_len = strlen(doc_root);
    if (strncmp(resolved_path, doc_root, root_len) != 0) {
        std::cout << "SECURITY: Path traversal - file outside doc_root!" << std::endl;
        std::cout << "  Resolved: " << resolved_path << std::endl;
        std::cout << "  Doc root: " << doc_root << std::endl;
        return FORBIDDEN_REQUEST;
    }
    
    memset(m_real_file, '\0', FILENAME_LEN);
    strncpy(m_real_file, resolved_path, FILENAME_LEN - 1);
    
    std::cout << "DEBUG: Final resolved file path: " << m_real_file << std::endl;
    
    if (stat(m_real_file, &m_file_stat) < 0) {
        std::cout << "ERROR: stat failed for file: " << m_real_file 
                  << ", errno: " << errno << std::endl;
        return NO_RESOURCE;
    }
    
    if (!(m_file_stat.st_mode & S_IROTH)) {
        std::cout << "ERROR: File not readable: " << m_real_file << std::endl;
        return FORBIDDEN_REQUEST;
    }
    
    if (S_ISDIR(m_file_stat.st_mode)) {
        std::cout << "ERROR: Path is a directory: " << m_real_file << std::endl;
        return BAD_REQUEST;
    }
    
    int fd = open(m_real_file, O_RDONLY);
    if (fd < 0) {
        std::cout << "ERROR: Failed to open file: " << m_real_file 
                  << ", errno: " << errno << std::endl;
        return INTERNAL_ERROR;
    }
    
    m_file_address = (char *)mmap(0, m_file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m_file_address == MAP_FAILED) {
        std::cout << "ERROR: mmap failed for file: " << m_real_file 
                  << ", errno: " << errno << std::endl;
        close(fd);
        return INTERNAL_ERROR;
    }
    
    close(fd);
    std::cout << "DEBUG: File mapped successfully, size: " << m_file_stat.st_size << " bytes" << std::endl;
    return FILE_REQUEST;
}
// XSS 防护工具函数实现
bool http_conn::has_xss_keywords(const char* str) {
    if (!str) return false;

    const char* keywords[] = {
        "<script", "</script", "javascript:", "onload=", "onerror=",
        "onclick=", "onmouseover=", "eval(", "alert(", "document.cookie",
        "window.location", "<iframe", "</iframe", "<img src=", "<svg/onload",
        "<body onload", "<input onfocus", "<marquee onstart", "<video onstart",
        "<audio onstart", "<applet", "<embed", "<object", "<meta", nullptr
    };

    // 使用栈上缓冲区，避免动态分配
    char lower_str[http_conn::MAX_STRING_LEN];
    size_t len = strlen(str);
    if (len >= sizeof(lower_str)) len = sizeof(lower_str) - 1;
    strncpy(lower_str, str, len);
    lower_str[len] = '\0';

    for (char* p = lower_str; *p; ++p) {
        *p = tolower(static_cast<unsigned char>(*p));
    }

    for (int i = 0; keywords[i] != nullptr; i++) {
        if (strstr(lower_str, keywords[i]) != nullptr) {
            return true;
        }
    }

    // 检查 HTML 实体编码绕过
    if (strstr(lower_str, "&#") && strstr(lower_str, ";")) {
        return true;
    }

    return false;
}

void http_conn::sanitize_input(char* input, size_t max_len) {
    if (!input || max_len == 0) return;

    char* src = input;
    char* dst = input;
    size_t len = 0;

    while (*src && len < max_len - 1) {
        if (*src == '<' || *src == '>' || *src == '\"' || *src == '\'' ||
            *src == '&' || *src == '(' || *src == ')' || *src == ';') {
            const char* replace = nullptr;
            size_t repl_len = 0;

            switch (*src) {
                case '<':  replace = "&lt;";   repl_len = 4; break;
                case '>':  replace = "&gt;";   repl_len = 4; break;
                case '\"': replace = "&quot;"; repl_len = 6; break;
                case '\'': replace = "&#39;";  repl_len = 5; break;
                case '&':  replace = "&amp;";  repl_len = 5; break;
                default: src++; continue;
            }

            if (len + repl_len < max_len) {
                memcpy(dst, replace, repl_len);
                dst += repl_len;
                len += repl_len;
            } else {
                break; // 空间不足，截断
            }
            src++;
        } else {
            *dst++ = *src++;
            len++;
        }
    }
    *dst = '\0';
}

bool http_conn::is_input_valid(const char* input, size_t max_len) {
    if (!input) return false;
    size_t input_len = strlen(input);
    return (input_len > 0 && input_len <= max_len);
}
void http_conn::unmap()
{
    if (m_file_address)
    {
        munmap(m_file_address, m_file_stat.st_size);
        m_file_address = 0;
    }
}
bool http_conn::write() {
    if (bytes_to_send == 0) {
        modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
        init();
        return true;
    }

    int temp = 0;

    if (m_is_https) {
        // 使用 SSL_write 分段发送
        while (bytes_have_send < bytes_to_send) {
            size_t iov_offset = 0;
            const char* buf_to_send = nullptr;
            size_t len_to_send = 0;

            // 确定当前要发送的数据块
            if (bytes_have_send < m_iv[0].iov_len) {
                buf_to_send = (const char*)m_iv[0].iov_base + bytes_have_send;
                len_to_send = m_iv[0].iov_len - bytes_have_send;
            } else {
                size_t offset_in_file = bytes_have_send - m_iv[0].iov_len;
                buf_to_send = (const char*)m_iv[1].iov_base + offset_in_file;
                len_to_send = m_iv[1].iov_len - offset_in_file;
            }

            temp = ssl_write(buf_to_send, len_to_send);
            if (temp > 0) {
                bytes_have_send += temp;
                bytes_to_send -= temp;
            } else {
                int ssl_err = SSL_get_error(m_ssl, temp);
                if (ssl_err == SSL_ERROR_WANT_WRITE) {
                    // 需要重试写
                    modfd(m_epollfd, m_sockfd, EPOLLOUT, m_TRIGMode);
                    return true;
                } else if (ssl_err == SSL_ERROR_WANT_READ) {
                    // SSL renegotiation 需要读（罕见）
                    modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
                    return true;
                } else {
                    unmap();
                    return false;
                }
            }
        }

        // 发送完成
        unmap();
        modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
        if (m_linger) {
            init();
            return true;
        } else {
            return false;
        }
    } else {
        // 原有 writev 逻辑
        while (1) {
            temp = writev(m_sockfd, m_iv, m_iv_count);
            if (temp < 0) {
                if (errno == EAGAIN) {
                    modfd(m_epollfd, m_sockfd, EPOLLOUT, m_TRIGMode);
                    return true;
                }
                unmap();
                return false;
            }
            bytes_have_send += temp;
            bytes_to_send -= temp;

            if (bytes_have_send >= m_iv[0].iov_len) {
                m_iv[0].iov_len = 0;
                m_iv[1].iov_base = m_file_address + (bytes_have_send - m_write_idx);
                m_iv[1].iov_len = bytes_to_send;
            } else {
                m_iv[0].iov_base = m_write_buf + bytes_have_send;
                m_iv[0].iov_len = m_iv[0].iov_len - bytes_have_send;
            }

            if (bytes_to_send <= 0) {
                unmap();
                modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
                if (m_linger) {
                    init();
                    return true;
                } else {
                    return false;
                }
            }
        }
    }
}
bool http_conn::add_response(const char *format, ...)
{
    if (m_write_idx >= WRITE_BUFFER_SIZE)
        return false;
    va_list arg_list;
    va_start(arg_list, format);
    int len = vsnprintf(m_write_buf + m_write_idx, WRITE_BUFFER_SIZE - 1 - m_write_idx, format, arg_list);
    if (len >= (WRITE_BUFFER_SIZE - 1 - m_write_idx))
    {
        va_end(arg_list);
        return false;
    }
    m_write_idx += len;
    va_end(arg_list);

    LOG_INFO("request:%s", m_write_buf);

    return true;
}
bool http_conn::add_status_line(int status, const char *title)
{
    return add_response("%s %d %s\r\n", "HTTP/1.1", status, title);
}
bool http_conn::add_headers(int content_len)
{
    return add_content_length(content_len) && add_linger() &&
           add_blank_line();
}
bool http_conn::add_content_length(int content_len)
{
    return add_response("Content-Length:%d\r\n", content_len);
}
bool http_conn::add_content_type()
{
    return add_response("Content-Type:%s\r\n", "text/html");
}
bool http_conn::add_linger()
{
    return add_response("Connection:%s\r\n", (m_linger == true) ? "keep-alive" : "close");
}
bool http_conn::add_blank_line()
{
    return add_response("%s", "\r\n");
}
bool http_conn::add_content(const char *content)
{
    return add_response("%s", content);
}
bool http_conn::process_write(HTTP_CODE ret)
{
    switch (ret)
    {
    case INTERNAL_ERROR:
    {
        add_status_line(500, error_500_title);
        add_headers(strlen(error_500_form));
        if (!add_content(error_500_form))
            return false;
        break;
    }
 
        case BAD_REQUEST:
    {
        add_status_line(400, error_400_title);  // 400 Bad Request
        add_headers(strlen(error_400_form));
        if (!add_content(error_400_form))
            return false;
        break;
    }
    case NO_RESOURCE:
    {
        add_status_line(404, error_404_title);  // 404 Not Found
        add_headers(strlen(error_404_form));
        if (!add_content(error_404_form))
            return false;
        break;
    }
    case FORBIDDEN_REQUEST:
    {
        add_status_line(403, error_403_title);
        add_headers(strlen(error_403_form));
        if (!add_content(error_403_form))
            return false;
        break;
    }
    case FILE_REQUEST:
    {
        add_status_line(200, ok_200_title);
        if (m_file_stat.st_size != 0)
        {
            add_headers(m_file_stat.st_size);
            m_iv[0].iov_base = m_write_buf;
            m_iv[0].iov_len = m_write_idx;
            m_iv[1].iov_base = m_file_address;
            m_iv[1].iov_len = m_file_stat.st_size;
            m_iv_count = 2;
            bytes_to_send = m_write_idx + m_file_stat.st_size;
            return true;
        }
        else
        {
            const char *ok_string = "<html><body></body></html>";
            add_headers(strlen(ok_string));
            if (!add_content(ok_string))
                return false;
        }
    }
    default:
        return false;
    }
    m_iv[0].iov_base = m_write_buf;
    m_iv[0].iov_len = m_write_idx;
    m_iv_count = 1;
    bytes_to_send = m_write_idx;
    return true;
}

void http_conn::process()
{
    HTTP_CODE read_ret = process_read();
    if (read_ret == NO_REQUEST)
    {
        modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
        return;
    }
    
    m_ret_code = read_ret;  // 保存处理结果
    
    // 如果是 CGI 请求，需要数据库连接
    if (cgi == 1) {
        // 如果有数据库连接池，从池中获取连接
        if (m_connPool && m_sql_num > 0 && !mysql) {
            connectionRAII mysqlcon(&mysql, m_connPool);
            
            if (!mysql) {
                LOG_ERROR("Failed to get MySQL connection for CGI request");
                m_ret_code = INTERNAL_ERROR;
            } else {
                LOG_INFO("MySQL connection acquired for CGI request");
            }
        } else if (!mysql) {
            // 没有数据库连接池，记录错误
            LOG_ERROR("No database connection available for CGI request");
            m_ret_code = INTERNAL_ERROR;
        }
    }
    
    bool write_ret = process_write(m_ret_code);
    if (!write_ret)
    {
        close_conn();
    }
    modfd(m_epollfd, m_sockfd, EPOLLOUT, m_TRIGMode);
}

// 重置连接状态（供连接池使用）
void http_conn::reset() {
    std::cout << "DEBUG: http_conn::reset() called" << std::endl;
       m_sockfd = -1;
    m_state = 0;
    m_read_idx = 0;
    m_checked_idx = 0;
    m_start_line = 0;
    m_write_idx = 0;
    m_check_state = CHECK_STATE_REQUESTLINE;
    m_method = GET;
    m_url = nullptr;
    m_version = nullptr;
    m_host = nullptr;
    m_content_length = 0;
    m_linger = false;
    bytes_to_send = 0;
    bytes_have_send = 0;
    cgi = 0;
    m_string = nullptr;
    timer_flag = 0;
    improv = 0;
    
    // 重置缓冲区
    memset(m_read_buf, 0, READ_BUFFER_SIZE);
    memset(m_write_buf, 0, WRITE_BUFFER_SIZE);
    memset(m_real_file, 0, FILENAME_LEN);
    
    // 释放内存映射
    unmap();
    
    m_file_address = nullptr;
    m_iv_count = 0;
    
    // 重置数据库连接
    mysql = nullptr;
       // 重置 SSL
    if (m_ssl) {
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }
    m_is_https = false;




    std::cout << "DEBUG: Connection reset" << std::endl;
}
