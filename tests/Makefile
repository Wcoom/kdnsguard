# kdnsguard 宿主侧单元测试
#
# 用宿主 gcc + ASan/UBSan 编译内核侧的 kdg_wire.c，而不是走 KUnit：
# 本树 CONFIG_KUNIT=m，案例在设备构建里根本不会被编译（见 test_wire.c 头注）。
# 同一份源文件两种编译形态，是保证「设备上跑的」和「测过的」是同一份代码的
# 唯一可靠做法——不复制源码，不建镜像副本。

CC      ?= gcc
BUILD   := build

# -fsanitize=address 抓越界读与 UAF；undefined 抓整数溢出、未对齐访问、
# 空指针解引用。DNS 解析器的全部风险都在这两类里。
CFLAGS  := -std=gnu11 -O1 -g -Wall -Wextra -Werror \
           -fsanitize=address,undefined -fno-omit-frame-pointer \
           -fno-sanitize-recover=all \
           -I../include -I../kernel -Iinclude

TARGET  := $(BUILD)/test_wire
SRC     := test_wire.c ../kernel/kdg_wire.c

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SRC) ../kernel/kdg_wire.h ../include/kdg_base.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(SRC)

$(BUILD):
	mkdir -p $(BUILD)

run: $(TARGET)
	@./$(TARGET)

clean:
	rm -rf $(BUILD)
