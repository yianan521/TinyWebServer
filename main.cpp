#include "config.h"
#include <unistd.h> 
int main(int argc, char *argv[])
{
    //使用简化的配置
    string user = "yianan";
    string passwd = "123456";
    string databasename = "yourdb";

    //命令行解析
    Config config;
    config.parse_arg(argc, argv);

    WebServer server;
char server_path[200];
getcwd(server_path, 200);
printf("Current directory: %s\n", server_path);
if (config.USE_HTTPS) {
    server.init_ssl(config.SSL_CERT_PATH.c_str(), config.SSL_KEY_PATH.c_str());
}
    //初始化（设置sql_num为实际连接数）
    // 注意：这里sql_num=5，表示初始化5个数据库连接
    server.init(config.PORT, user, passwd, databasename, config.LOGWrite,
                config.OPT_LINGER, config.TRIGMode, 5,  // sql_num=5，启用数据库
                config.thread_num, config.close_log, config.actor_model);

    //日志
    server.log_write();

    // 必须调用数据库连接池初始化！
    server.sql_pool();

    //线程池
    server.thread_pool();

    // ===== 启用HTTP连接池 =====
    printf("\n=================================\n");
    printf("高性能HTTP服务器启动\n");
    printf("端口: %d\n", config.PORT);
    printf("线程数: %d\n", config.thread_num);
    printf("=================================\n\n");

    // 初始化HTTP连接池（100个连接）
    server.init_conn_pool(100);

    //触发模式
    server.trig_mode();

    //监听
    server.eventListen();  // 这里可能失败

    //运行
    printf("\n=== 服务器开始运行 ===\n");
    printf("模式: %s\n", server.m_use_conn_pool ? "连接池模式" : "传统模式");
    printf("等待客户端连接...\n");

    server.eventLoop();

    printf("\n=== 服务器停止 ===\n");
    return 0;
}
