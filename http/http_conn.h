// http_conn.h
#ifndef HTTPCONNECTION_H
#define HTTPCONNECTION_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <string.h>
#include <sys/uio.h>
#include <map>
#include <string>
#include <iostream> // 👈 必须包含以使用 std::cout

#include "../lock/locker.h"
#include "../log/log.h"
#include "../CGImysql/sql_connection_pool.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

class http_conn {
public:
    // ===== 常量定义 =====
    static const int MAX_POST_SIZE = 1024 * 1024;
    static const int MAX_USERNAME_LEN = 100;
    static const int MAX_PASSWORD_LEN = 100;
    static const int MAX_STRING_LEN = 8192;
    static const int FILENAME_LEN = 200;
    static const int READ_BUFFER_SIZE = 2048;
    static const int WRITE_BUFFER_SIZE = 1024;

    // ===== 枚举定义 =====
    enum METHOD { GET = 0, POST, HEAD, PUT, DELETE, TRACE, OPTIONS, CONNECT, PATCH };
    enum CHECK_STATE { CHECK_STATE_REQUESTLINE = 0, CHECK_STATE_HEADER, CHECK_STATE_CONTENT };
    enum LINE_STATUS { LINE_OK = 0, LINE_BAD, LINE_OPEN };
    enum HTTP_CODE { NO_REQUEST, GET_REQUEST, BAD_REQUEST, NO_RESOURCE, FORBIDDEN_REQUEST, FILE_REQUEST, INTERNAL_ERROR, CLOSED_CONNECTION };

    // ===== 静态成员 =====
    static int m_epollfd;
    static int m_user_count;

    // ===== SSL 相关成员 =====
    SSL* m_ssl = nullptr;
    bool m_is_https = false;
    bool m_ssl_handshake_done = false; // ✅ 在声明处初始化

    void set_ssl(SSL* ssl) {
        m_ssl = ssl;
        m_is_https = (ssl != nullptr);
    }
    int ssl_read(char* buf, int len);
    int ssl_write(const char* buf, int len);

    // ===== 构造/析构（仅声明）=====
    http_conn();
    ~http_conn();

    // ===== 公共接口 =====
    void init(int sockfd, const sockaddr_in& addr, char* root, int TRIGMode,
              int close_log, std::string user, std::string passwd, std::string sqlname);
    void reset();
    void close_conn(bool real_close = true);
    void process();
    bool read_once();
    bool write();

    sockaddr_in* get_address() { return &m_address; }
    MYSQL* get_mysql() { return mysql; }
    void set_mysql(MYSQL* conn) { mysql = conn; }
    void initmysql_result(connection_pool* connPool);

    // 定时器相关
    int timer_flag;
    int improv;

    // 数据库连接池
    connection_pool* m_connPool = nullptr;
    void set_conn_pool(connection_pool* pool) { m_connPool = pool; }

    // SQL 用户信息
    void set_sql_num(int sql_num) { m_sql_num = sql_num; }
    int get_sql_num() const { return m_sql_num; }

    // ===== 公有成员变量（按原项目保留）=====
    int m_state;
    int m_sockfd;
    sockaddr_in m_address;
    MYSQL* mysql = nullptr;
    char* doc_root = nullptr;

private:
    // ===== 私有成员变量 =====
    char m_read_buf[READ_BUFFER_SIZE];
    int m_read_idx;
    int m_checked_idx;
    int m_start_line;
    char m_write_buf[WRITE_BUFFER_SIZE];
    int m_write_idx;
    CHECK_STATE m_check_state;
    METHOD m_method;
    char m_real_file[FILENAME_LEN];
    char* m_url = nullptr;
    char* m_version = nullptr;
    char* m_host = nullptr;
    int m_content_length;
    bool m_linger;
    char* m_file_address = nullptr;
    struct stat m_file_stat;
    struct iovec m_iv[2];
    int m_iv_count;
    int cgi;
    char* m_string = nullptr;
    int bytes_to_send;
    int bytes_have_send;
    std::map<std::string, std::string> m_users;
    int m_TRIGMode;
    int m_close_log;
    char sql_user[100] = {0};
    char sql_passwd[100] = {0};
    char sql_name[100] = {0};
    int m_sql_num = 0;
    HTTP_CODE m_ret_code = NO_REQUEST;

    // ===== 私有方法 =====
    void init(); // 内部init
    HTTP_CODE process_read();
    bool process_write(HTTP_CODE ret);
    HTTP_CODE parse_request_line(char* text);
    HTTP_CODE parse_headers(char* text);
    HTTP_CODE parse_content(char* text);
    HTTP_CODE do_request();
    char* get_line() { return m_read_buf + m_start_line; }
    LINE_STATUS parse_line();
    void unmap();
    const char* get_stateinfo(int code);
    bool add_response(const char* format, ...);
    bool add_headers(int content_length);
    bool add_content(const char* content);
    bool add_status_line(int status, const char* title);
    bool add_content_length(int content_length);
    bool add_linger();
    bool add_content_type();
    bool add_blank_line();
    bool is_post_too_large() const {
        return m_content_length > MAX_POST_SIZE;
    }

    // XSS 防护
    static bool has_xss_keywords(const char* str);
    static void sanitize_input(char* input, size_t max_len);
    static bool is_input_valid(const char* input, size_t max_len);
    static bool url_decode(const char* src, char* dst, size_t dst_size);
};

#endif // HTTPCONNECTION_H