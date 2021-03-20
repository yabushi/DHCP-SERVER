TARGET = dhcp_server

SRCS = dhcp_server.c
OBJS = dhcp_server.o

CFLAGS = -I. -g
LIB    = 

OBJS_DIR = obj

$(TARGET): $(OBJS_DIR)/$(OBJS)
	$(CC) -o $@ $(OBJS_DIR)/$(OBJS) $(LIB)

$(OBJS_DIR)/$(OBJS): $(SRCS)
	@if [ ! -d $(OBJS_DIR) ]; then \
		echo ";; mkdir $(OBJS_DIR)"; mkdir $(OBJS_DIR); \
	fi
	$(CC) $(CFLAGS) -c $(SRCS) -o $(OBJS_DIR)/$(OBJS)

.PHONY: all clean
all: $(TARGET)

clean:
	rm -rf $(TARGET) $(OBJS_DIR)/$(OBJS) $(OBJS_DIR)