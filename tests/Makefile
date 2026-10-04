# kdnsguard 宿主侧单元测试
#
# 用宿主 gcc + ASan/UBSan 编译内核侧的双态模块（kdg_wire.c / kdg_http.c），
# 而不是走 KUnit：本树 CONFIG_KUNIT=m，案例在设备构建里根本不会被编译。
# 同一份源文件两种编译形态，是保证「设备上跑的」和「测过的」是同一份代码的
# 唯一可靠做法——不复制源码，不建镜像副本。

CC      ?= gcc
BUILD   := build

# -fsanitize=address 抓越界读与 UAF；undefined 抓整数溢出、未对齐访问、
# 空指针解引用。这两个模块的全部风险都在这两类里。
CFLAGS  := -std=gnu11 -O1 -g -Wall -Wextra -Werror \
           -fsanitize=address,undefined -fno-omit-frame-pointer \
           -fno-sanitize-recover=all \
           -I../include -I../kernel -Iinclude

WIRE    := $(BUILD)/test_wire
HTTP    := $(BUILD)/test_http
CACHE   := $(BUILD)/test_cache
CACHE_TAB := $(BUILD)/test_cache_tab
WIRE_SRC  := test_wire.c  ../kernel/kdg_wire.c
HTTP_SRC  := test_http.c  ../kernel/kdg_http.c
CACHE_SRC := test_cache.c ../kernel/kdg_cache.c ../kernel/kdg_wire.c

.PHONY: all run clean

all: $(WIRE) $(HTTP) $(CACHE) $(CACHE_TAB)

$(WIRE): $(WIRE_SRC) ../kernel/kdg_wire.h ../include/kdg_base.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(WIRE_SRC)

$(HTTP): $(HTTP_SRC) ../kernel/kdg_http.h ../include/kdg_base.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(HTTP_SRC)

$(CACHE): $(CACHE_SRC) ../kernel/kdg_cache.h ../kernel/kdg_wire.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(CACHE_SRC)

$(CACHE_TAB): test_cache_tab.c host_kernel.h ../kernel/kdg_cache_tab.c ../kernel/kdg_cache_tab.h ../kernel/kdg_cache.c ../kernel/kdg_wire.c | $(BUILD)
	$(CC) $(CFLAGS) -pthread -I. -DKDG_HOST_TEST -o $@ test_cache_tab.c ../kernel/kdg_cache.c ../kernel/kdg_wire.c

$(BUILD):
	mkdir -p $(BUILD)

run: all
	@./$(WIRE)
	@./$(HTTP)
	@./$(CACHE)
	@./$(CACHE_TAB)

clean:
	rm -rf $(BUILD)
