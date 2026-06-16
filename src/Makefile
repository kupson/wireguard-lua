MODULE := wireguard.so
OBJS := wireguard_lua.o wireguard.o

CFLAGS += -D_GNU_SOURCE $(LUA_CFLAGS)
LDFLAGS += $(LUA_LIBS)

all: $(MODULE)

$(MODULE): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c wireguard.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(MODULE)
