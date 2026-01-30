#include "webserver.h"
#include <iostream>
#include <dirent.h>
WebServer::WebServer()
{
//http_conn类对象
    users = new http_conn*[MAX_FD];
    for (int i = 0; i < MAX_FD; ++i) {
        users[i] = nullptr;  // 初始化为空
    }

    // ============ 设置根目录路径 ============
    char server_path[1024];
    
    // 获取当前工作目录
    if (getcwd(server_path, sizeof(server_path)) != NULL) {
        printf("当前工作目录: %s\n", server_path);
        
        // 构建 root 目录的完整路径
        char full_path[2048];
        snprintf(full_path, sizeof(full_path), "%s/root", server_path);
        
        m_root = strdup(full_path);
        printf("设置服务器根目录为: %s\n", m_root);
    } else {
        // 回退方案：使用相对路径
        printf("警告: 无法获取当前目录\n");
        m_root = strdup("./root");
        printf("使用相对路径: ./root\n");
    }
    
    // 验证目录是否存在
    struct stat st;
    if (stat(m_root, &st) == 0 && S_ISDIR(st.st_mode)) {
        printf("✓ 根目录验证成功\n");
        
        // 列出目录内容验证
        printf("根目录内容:\n");
        DIR *dir = opendir(m_root);
        if (dir) {
            struct dirent *entry;
            int count = 0;
            while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                    printf("  - %s\n", entry->d_name);
                    count++;
                }
            }
            closedir(dir);
            printf("总计 %d 个文件\n", count);
            
            // 特别检查关键文件
            const char* key_files[] = {"judge.html", "welcome.html", "index.html", "test.txt", NULL};
            for (int i = 0; key_files[i]; i++) {
                char file_path[4096];
                snprintf(file_path, sizeof(file_path), "%s/%s", m_root, key_files[i]);
                if (access(file_path, F_OK) == 0) {
                    printf("✓ 关键文件存在: %s\n", key_files[i]);
                } else {
                    printf("⚠ 警告: 关键文件不存在: %s\n", key_files[i]);
                }
            }
        } else {
            printf("✗ 无法打开根目录\n");
        }
    } else {
        printf("✗ 错误: 根目录不存在或不是目录: %s\n", m_root);
        printf("请确保在项目根目录下运行服务器\n");
        
        // 尝试使用绝对路径
        char* home = getenv("HOME");
        if (home) {
            char abs_path[1024];
            snprintf(abs_path, sizeof(abs_path), "%s/T/MyWebServer-master/root", home);
            if (access(abs_path, F_OK) == 0) {
                printf("尝试使用绝对路径: %s\n", abs_path);
                free(m_root);
                m_root = strdup(abs_path);
            }
        }
    }
    // ======================================

    //定时器
    users_timer = new client_data[MAX_FD];
    
    // 连接池使用标志初始化（默认不使用）
    m_use_conn_pool = false;
}

WebServer::~WebServer()
{
    close(m_epollfd);
    close(m_listenfd);
    close(m_pipefd[1]);
    close(m_pipefd[0]);
    delete[] users;
    delete[] users_timer;
    delete m_pool;
}

void WebServer::init(int port, string user, string passWord, string databaseName, int log_write, 
                     int opt_linger, int trigmode, int sql_num, int thread_num, int close_log, int actor_model)
{
    m_port = port;
    m_user = user;
    m_passWord = passWord;
    m_databaseName = databaseName;
    m_sql_num = sql_num;
    m_thread_num = thread_num;
    m_log_write = log_write;
    m_OPT_LINGER = opt_linger;
    m_TRIGMode = trigmode;
    m_close_log = close_log;
    m_actormodel = actor_model;
}

void WebServer::trig_mode()
{
    //LT + LT
    if (0 == m_TRIGMode)
    {
        m_LISTENTrigmode = 0;
        m_CONNTrigmode = 0;
    }
    //LT + ET
    else if (1 == m_TRIGMode)
    {
        m_LISTENTrigmode = 0;
        m_CONNTrigmode = 1;
    }
    //ET + LT
    else if (2 == m_TRIGMode)
    {
        m_LISTENTrigmode = 1;
        m_CONNTrigmode = 0;
    }
    //ET + ET
    else if (3 == m_TRIGMode)
    {
        m_LISTENTrigmode = 1;
        m_CONNTrigmode = 1;
    }
}

void WebServer::init_ssl(const char* cert_path, const char* key_path) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    m_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!m_ssl_ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(m_ssl_ctx, cert_path, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(m_ssl_ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(m_ssl_ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }

    m_use_https = true;
    printf("✓ HTTPS (SSL/TLS) initialized with cert: %s, key: %s\n", cert_path, key_path);
}

SSL* WebServer::create_ssl(int sockfd) {
    SSL* ssl = SSL_new(m_ssl_ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return nullptr;
    }
    return ssl;
}


void WebServer::log_write()
{
    if (0 == m_close_log)
    {
        //初始化日志
        if (1 == m_log_write)
            Log::get_instance()->init("./logs/ServerLog", m_close_log, 2000, 800000, 800);
        else
            Log::get_instance()->init("./logs/ServerLog", m_close_log, 2000, 800000, 0);
    }
}
void WebServer::sql_pool()
{
    // 创建连接池对象，但不真正初始化数据库连接
    m_connPool = connection_pool::GetInstance();
    
    std::cout << "\n=== 初始化数据库连接池 ===" << std::endl;
    std::cout << "DEBUG: sql_num = " << m_sql_num << std::endl;
    
    // 只有在需要数据库时才真正初始化
    if (m_sql_num > 0) {
        std::cout << "DEBUG: Initializing MySQL connection pool..." << std::endl;
        std::cout << "DEBUG: User: " << m_user << std::endl;
        std::cout << "DEBUG: Database: " << m_databaseName << std::endl;
        
        // 直接调用，init() 返回 void
        m_connPool->init("localhost", m_user, m_passWord, 
                        m_databaseName, 3306, m_sql_num, m_close_log);
        
        std::cout << "✓ 数据库连接池初始化完成" << std::endl;
        
        // 初始化用户数据 - users 是 http_conn**，需要通过正确的对象调用
        // 我们需要创建一个 http_conn 对象来调用 initmysql_result
        if (MAX_FD > 0) {
            http_conn temp_conn;
            temp_conn.initmysql_result(m_connPool);
            std::cout << "✓ 用户数据初始化完成" << std::endl;
        }
        
    } else {
        std::cout << "DEBUG: Database connection disabled (sql_num = 0)" << std::endl;
        std::cout << "WARNING: CGI functionality will not work" << std::endl;
    }
}

void WebServer::thread_pool()
{   if (!m_connPool) {
        m_connPool = connection_pool::GetInstance();
        // 不初始化数据库连接，但对象存在
    }
    //线程池
    m_pool = new threadpool<http_conn>(m_actormodel, m_connPool, m_thread_num);
}

void WebServer::eventListen()
{
    //网络编程基础步骤
    m_listenfd = socket(PF_INET, SOCK_STREAM, 0);
    assert(m_listenfd >= 0);

    //优雅关闭连接
    if (0 == m_OPT_LINGER)
    {
        struct linger tmp = {0, 1};
        setsockopt(m_listenfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof(tmp));
    }
    else if (1 == m_OPT_LINGER)
    {
        struct linger tmp = {1, 1};
        setsockopt(m_listenfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof(tmp));
    }

    int ret = 0;
    struct sockaddr_in address;
    bzero(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(m_port);

    int flag = 1;
    setsockopt(m_listenfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    ret = bind(m_listenfd, (struct sockaddr *)&address, sizeof(address));
    assert(ret >= 0);
    ret = listen(m_listenfd, 5);
    if (ret < 0) {
    perror("listen error");
    fprintf(stderr, "Failed to listen on port %d\n", m_port);
    exit(1);
}
    assert(ret >= 0);

    utils.init(TIMESLOT);

    //epoll创建内核事件表

    m_epollfd = epoll_create(5);
    assert(m_epollfd != -1);

    utils.addfd(m_epollfd, m_listenfd, false, m_LISTENTrigmode);
    http_conn::m_epollfd = m_epollfd;

    ret = socketpair(PF_UNIX, SOCK_STREAM, 0, m_pipefd);
    assert(ret != -1);
    utils.setnonblocking(m_pipefd[1]);
    utils.addfd(m_epollfd, m_pipefd[0], false, 0);

    utils.addsig(SIGPIPE, SIG_IGN);
    utils.addsig(SIGALRM, utils.sig_handler, false);
    utils.addsig(SIGTERM, utils.sig_handler, false);

    alarm(TIMESLOT);

    //工具类,信号和描述符基础操作
    Utils::u_pipefd = m_pipefd;
    Utils::u_epollfd = m_epollfd;
}

// 初始化连接池
void WebServer::init_conn_pool(int size) {
    printf("=== 初始化HTTP连接池 ===\n");
    SimpleConnPool::getInstance()->init(size);
    m_use_conn_pool = true;
    printf("连接池初始化完成，大小: %d\n", size);
    show_pool_stats();
}

// 显示连接池统计
void WebServer::show_pool_stats() {
    if (m_use_conn_pool) {
        int freeCount, usedCount, totalCount;
        SimpleConnPool::getInstance()->getStats(freeCount, usedCount, totalCount);
        printf("连接池统计: 空闲=%d, 使用中=%d, 总容量=%d, 利用率=%.1f%%\n",
               freeCount, usedCount, totalCount, 
               (usedCount * 100.0) / totalCount);
    }
}

//若有数据传输，则将定时器往后延迟3个单位
//并对新的定时器在链表上的位置进行调整
void WebServer::adjust_timer(util_timer *timer)
{
    time_t cur = time(NULL);
    timer->expire = cur + 3 * TIMESLOT;
    utils.m_timer_lst.adjust_timer(timer);

    LOG_INFO("%s", "adjust timer once");
}

void WebServer::timer(int connfd, struct sockaddr_in client_address)
{
    http_conn* conn = nullptr;
    
    if (m_use_conn_pool) {
        // 从连接池获取连接
     conn = SimpleConnPool::getInstance()->acquire();
        printf("连接池[获取]: 为客户端 fd=%d 分配连接\n", connfd);
             // 设置数据库连接池
        if (m_connPool && m_sql_num > 0) {
            conn->set_conn_pool(m_connPool);
        }

        // 初始化连接
        conn->init(connfd, client_address, m_root, m_CONNTrigmode, 
                   m_close_log, m_user, m_passWord, m_databaseName);
        
             if (m_use_https) {
    SSL* ssl = SSL_new(m_ssl_ctx);  // 使用 WebServer 的 SSL_CTX
    if (!ssl) {
        LOG_ERROR("SSL_new failed for fd=%d", connfd);
        // 处理错误（如关闭 connfd）
        return;
    }
    SSL_set_fd(ssl, connfd);
    conn->set_ssl(ssl);  // 这会设置 m_is_https = true
}      
        // 将连接复制到 users 数组以保持兼容性
        users[connfd] = conn;
    } else {
        // 传统方式：
        conn = new http_conn();
        conn->init(connfd, client_address, m_root, m_CONNTrigmode,
                   m_close_log, m_user, m_passWord, m_databaseName);
        users[connfd] = conn;  
    }

    //初始化client_data数据
    //创建定时器，设置回调函数和超时时间，绑定用户数据，将定时器添加到链表中
    users_timer[connfd].address = client_address;
    users_timer[connfd].sockfd = connfd;
    util_timer *timer = new util_timer;
    timer->user_data = &users_timer[connfd];
    timer->cb_func = cb_func;
    time_t cur = time(NULL);
    timer->expire = cur + 3 * TIMESLOT;
    users_timer[connfd].timer = timer;
    utils.m_timer_lst.add_timer(timer);
    
    // 显示连接池统计
    if (m_use_conn_pool) {
        show_pool_stats();
    }
}
void WebServer::deal_timer(util_timer* timer, int sockfd) {
    if (timer) {
        // 获取连接指针
        http_conn* conn = users[sockfd];
        
        if (conn) {
            // 重置连接状态
            conn->reset();
            
            // 如果使用连接池，归还连接
            if (m_use_conn_pool) {
                SimpleConnPool::getInstance()->release(conn);
                printf("连接池[释放]: 连接 fd=%d 已归还\n", sockfd);
                show_pool_stats();
            } else {
                // 传统方式：删除对象
                delete conn;
            }
            
            users[sockfd] = nullptr;  // 清空指针
        }
        
        timer->cb_func(&users_timer[sockfd]);
        if (timer == users_timer[sockfd].timer) {
            users_timer[sockfd].timer = NULL;
        }
        delete timer;
    }
}

bool WebServer::dealclientdata()
{
    struct sockaddr_in client_address;
    socklen_t client_addrlength = sizeof(client_address);
    if (0 == m_LISTENTrigmode)
    {
        int connfd = accept(m_listenfd, (struct sockaddr *)&client_address, &client_addrlength);
        if (connfd < 0)
        {
            LOG_ERROR("%s:errno is:%d", "accept error", errno);
            return false;
        }
        if (http_conn::m_user_count >= MAX_FD)
        {
            utils.show_error(connfd, "Internal server busy");
            LOG_ERROR("%s", "Internal server busy");
            return false;
        }
        timer(connfd, client_address);
    }

    else
    {
        while (1)
        {
            int connfd = accept(m_listenfd, (struct sockaddr *)&client_address, &client_addrlength);
            if (connfd < 0)
            {
                LOG_ERROR("%s:errno is:%d", "accept error", errno);
                break;
            }
            if (http_conn::m_user_count >= MAX_FD)
            {
                utils.show_error(connfd, "Internal server busy");
                LOG_ERROR("%s", "Internal server busy");
                break;
            }
            timer(connfd, client_address);
        }
        return false;
    }
    return true;
}

bool WebServer::dealwithsignal(bool &timeout, bool &stop_server)
{
    int ret = 0;
    int sig;
    char signals[1024];
    ret = recv(m_pipefd[0], signals, sizeof(signals), 0);
    if (ret == -1)
    {
        return false;
    }
    else if (ret == 0)
    {
        return false;
    }
    else
    {
        for (int i = 0; i < ret; ++i)
        {
            switch (signals[i])
            {
            case SIGALRM:
            {
                timeout = true;
                break;
            }
            case SIGTERM:
            {
                stop_server = true;
                break;
            }
            }
        }
    }
    return true;
}

void WebServer::dealwithread(int sockfd)
{
    util_timer *timer = users_timer[sockfd].timer;

    //reactor
    if (1 == m_actormodel)
    {
        if (timer)
        {
            adjust_timer(timer);
        }

        //若监测到读事件，将该事件放入请求队列
        m_pool->append(users[sockfd], 0);

        while (true)
        {
            if (1 == users[sockfd]->improv)
            {
                if (1 == users[sockfd]->timer_flag)
                {
                    deal_timer(timer, sockfd);
                    users[sockfd]->timer_flag = 0;
                }
                users[sockfd]->improv = 0;
                break;
            }
        }
    }
    else
    {
        //proactor
        if (users[sockfd]->read_once())
        {
            LOG_INFO("deal with the client(%s)", inet_ntoa(users[sockfd]->get_address()->sin_addr));

            //若监测到读事件，将该事件放入请求队列
            m_pool->append_p(users[sockfd]);

            if (timer)
            {
                adjust_timer(timer);
            }
        }
        else
        {
            deal_timer(timer, sockfd);
        }
    }
}

void WebServer::dealwithwrite(int sockfd)
{
    util_timer *timer = users_timer[sockfd].timer;
    //reactor
    if (1 == m_actormodel)
    {
        if (timer)
        {
            adjust_timer(timer);
        }

        m_pool->append(users[sockfd], 1);

        while (true)
        {
            if (1 == users[sockfd]->improv)
            {
                if (1 == users[sockfd]->timer_flag)
                {
                    deal_timer(timer, sockfd);
                    users[sockfd]->timer_flag = 0;
                }
                users[sockfd]->improv = 0;
                break;
            }
        }
    }
    else
    {
        //proactor
        if (users[sockfd]->write())
        {
            LOG_INFO("send data to the client(%s)", inet_ntoa(users[sockfd]->get_address()->sin_addr));

            if (timer)
            {
                adjust_timer(timer);
            }
        }
        else
        {
            deal_timer(timer, sockfd);
        }
    }
}

void WebServer::eventLoop() {
    bool timeout = false;
    bool stop_server = false;

    while (!stop_server) {
        int number = epoll_wait(m_epollfd, events, MAX_EVENT_NUMBER, -1);
        if (number < 0 && errno != EINTR) {
            break;
        }

        for (int i = 0; i < number; i++) {
            int sockfd = events[i].data.fd;

            // 处理新到的客户端连接
            if (sockfd == m_listenfd) {
                bool flag = dealclientdata();
                if (false == flag)
                    continue;
            } else if (events[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
                // 服务器端关闭连接
                util_timer* timer = users_timer[sockfd].timer;
                deal_timer(timer, sockfd);
            } else if ((sockfd == m_pipefd[0]) && (events[i].events & EPOLLIN)) {
                // 处理信号
                bool flag = dealwithsignal(timeout, stop_server);
                if (false == flag)
                    Log::get_instance()->write_log(1, "dealclientdata failure");
            } else if (events[i].events & EPOLLIN) {
                dealwithread(sockfd);
            } else if (events[i].events & EPOLLOUT) {
                dealwithwrite(sockfd);
            }
        }
        if (timeout) {
            utils.timer_handler();
            Log::get_instance()->write_log(0, "timer tick");
            timeout = false;
        }
    }
}
