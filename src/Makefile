MODULE := wireguard.so
OBJS := wireguard_lua.o wireguard.o

CPPFLAGS += $(LUA_CFLAGS)
LDLIBS += $(LUA_LIBS)

all: $(MODULE)

$(MODULE): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

%.o: %.c wireguard.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(MODULE)
