CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include

SRC_DIR = src
OBJ_DIR = obj
TARGET = 8ompscan

SRCS = $(SRC_DIR)/main.c \
		$(SRC_DIR)/banner.c \
		$(SRC_DIR)/scan_connect.c \
		$(SRC_DIR)/scan_syn.c

OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean