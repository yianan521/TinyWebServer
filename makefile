# 编译器
CXX = g++
CXXFLAGS = -g -Wall -std=c++11 -pthread -I./include

# 目标文件
TARGET = server

# 源文件
SRCS = main.cpp \
       timer/lst_timer.cpp \
       http/http_conn.cpp \
       log/log.cpp \
       CGImysql/sql_connection_pool.cpp \
       webserver.cpp \
       config.cpp

# 库文件
LIBS = -lpthread -lmysqlclient -lssl -lcrypto

# 目标文件
OBJS = $(SRCS:.cpp=.o)

# 默认目标
all: $(TARGET)

# 链接目标
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# 编译规则
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 清理
clean:
	rm -f $(OBJS) $(TARGET)

# 伪目标
.PHONY: all clean
