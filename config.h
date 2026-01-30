#ifndef CONFIG_H
#define CONFIG_H

#include "webserver.h"

using namespace std;

class Config
{
public:
    Config();
    ~Config(){};

    void parse_arg(int argc, char*argv[]);

    //端口号
    int PORT;

    //日志写入方式 0:同步 1:异步
    int LOGWrite;

    //触发组合模式
    int TRIGMode;

    //listenfd触发模式
    int LISTENTrigmode;

    //connfd触发模式
    int CONNTrigmode;

    //优雅关闭链接
    int OPT_LINGER;

    //数据库连接池数量
    int sql_num;

    //线程池内的线程数量
    int thread_num;

    //是否关闭日志
    int close_log;

    //并发模型选择
    int actor_model;

       // HTTP连接池大小
    int http_conn_pool_size;
    
    // HTTP连接超时时间（秒）
    int http_conn_timeout;
    // 新增：异步日志队列大小
    int log_queue_size;

    int USE_HTTPS;          // 👈 新增：0=HTTP, 1=HTTPS
    int HTTPS_PORT;         // 👈 新增：如 443
    string SSL_CERT_PATH;   // 👈 新增：证书路径
    string SSL_KEY_PATH;    // 👈 新增：私钥路径


};

#endif
