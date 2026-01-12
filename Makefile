CC      ?= gcc
CFLAGS  ?= -std=c17 -g -Wall -Werror -pedantic
CPPFLAGS?= -Iinclude
LDFLAGS ?=

SAN_CFLAGS  = -O1 -g -fno-omit-frame-pointer
SAN_LDFLAGS = -fsanitize=address,undefined

BUILD := build
BIN   := bin

SERVER_SRCS := \
  src/server/server.c \
  src/server/protocol.c \
  src/ds/db.c \
  src/ds/zset.c \
  src/ds/hashtable.c \
  src/ds/avltree.c

CLIENT_SRCS := src/client/client.c

TEST_PROTOCOL_SRCS := tests/protocol_test.c src/server/protocol.c
TEST_AVL_SRCS      := tests/avltree_test.c  src/ds/avltree.c
TEST_ZSET_SRCS     := tests/zset_test.c     src/ds/zset.c src/ds/avltree.c src/ds/hashtable.c
TEST_DB_SRCS       := tests/db_test.c       src/ds/db.c src/ds/hashtable.c src/ds/zset.c src/ds/avltree.c src/server/protocol.c

SERVER_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(SERVER_SRCS))
CLIENT_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CLIENT_SRCS))

TEST_PROTOCOL_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(TEST_PROTOCOL_SRCS))
TEST_AVL_OBJS      := $(patsubst %.c,$(BUILD)/%.o,$(TEST_AVL_SRCS))
TEST_ZSET_OBJS     := $(patsubst %.c,$(BUILD)/%.o,$(TEST_ZSET_SRCS))
TEST_DB_OBJS       := $(patsubst %.c,$(BUILD)/%.o,$(TEST_DB_SRCS))
TEST_BLACKBOX_OBJ  := $(BUILD)/tests/server_blackbox_test.o

.PHONY: all clean test asan asan-test
all: client server

# Compile any .c into a mirrored build/ path (e.g. build/src/ds/db.o)
$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

client: $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BIN)/protocol_test: $(TEST_PROTOCOL_OBJS)
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BIN)/avltree_test: $(TEST_AVL_OBJS)
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BIN)/zset_test: $(TEST_ZSET_OBJS)
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BIN)/db_test: $(TEST_DB_OBJS)
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

# Note: this target does NOT link server objects; it depends on the server binary existing.
$(BIN)/server_blackbox_test: $(TEST_BLACKBOX_OBJ) server
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TEST_BLACKBOX_OBJ)

test: $(BIN)/protocol_test $(BIN)/avltree_test $(BIN)/zset_test $(BIN)/db_test $(BIN)/server_blackbox_test
	./$(BIN)/protocol_test
	./$(BIN)/avltree_test
	./$(BIN)/zset_test
	./$(BIN)/db_test
	./$(BIN)/server_blackbox_test

asan:
	$(MAKE) clean
	$(MAKE) all CFLAGS="$(CFLAGS) $(SAN_CFLAGS)" LDFLAGS="$(LDFLAGS) $(SAN_LDFLAGS)"

asan-test:
	$(MAKE) clean
	$(MAKE) test CFLAGS="$(CFLAGS) $(SAN_CFLAGS)" LDFLAGS="$(LDFLAGS) $(SAN_LDFLAGS)"

clean:
	$(RM) -r $(BUILD) $(BIN)
	$(RM) server client
