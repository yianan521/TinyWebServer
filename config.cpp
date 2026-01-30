#include "config.h"
#include <unistd.h>
#include <stdlib.h>
Config::Config(){
    //端口号,默认9006
    PORT = 9006;
   HTTPS_PORT = 443;
    USE_HTTPS = 1;
       SSL_CERT_PATH = "./server.crt";   // 默认路径
    SSL_KEY_PATH = "./server.key";
    //日志写入方式，默认异步
    LOGWrite = 1;  // 0:同步，1:异步

    //触发组合模式,默认listenfd LT + connfd LT
    TRIGMode = 0;

    //listenfd触发模式，默认LT
    LISTENTrigmode = 0;

    //connfd触发模式，默认LT
    CONNTrigmode = 0;

    //优雅关闭链接，默认不使用
    OPT_LINGER = 0;

    //数据库连接池数量,默认8
    sql_num = 8;

    //线程池内的线程数量,默认8
    thread_num = 8;

    //关闭日志,默认不关闭
    close_log = 0;

    //并发模型,默认是proactor
    actor_model = 0;
    
    // 新增：异步日志队列大小，默认1000
    log_queue_size = 1000;
        // HTTP连接池大小,默认100
    http_conn_pool_size = 100;
    
    // HTTP连接超时时间,默认15秒
    http_conn_timeout = 15;
}

void Config::parse_arg(int argc, char*argv[]){
    int opt;
    const char *str = "p:l:m:o:s:t:c:a:q:h:H:";
    while ((opt = getopt(argc, argv, str)) != -1)
    {
        switch (opt)
        {
        case 'p':
        {
            PORT = atoi(optarg);
            break;
        }
        case 'l':
        {
            LOGWrite = atoi(optarg);
            break;
        }
        case 'm':
        {
            TRIGMode = atoi(optarg);
            break;
        }
        case 'o':
        {
            OPT_LINGER = atoi(optarg);
            break;
        }
        case 's':
        {
            sql_num = atoi(optarg);
            break;
        }
        case 't':
        {
            thread_num = atoi(optarg);
            break;
        }
        case 'c':
        {
            close_log = atoi(optarg);
            break;
        }
        case 'a':
        {
            actor_model = atoi(optarg);
            break;
        }
        case 'q':  // 新增：日志队列大小参数
        {
            log_queue_size = atoi(optarg);
            break;
        }
          case 'h':  // HTTP连接池大小
        {
            http_conn_pool_size = atoi(optarg);
            break;
        }
        case 'H':  // HTTP连接超时时间
        {
            http_conn_timeout = atoi(optarg);
            break;
        }
        default:
            break;
        }
    }
}
