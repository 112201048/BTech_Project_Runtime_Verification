CFLAGS = $(shell pkg-config --cflags glib-2.0)
LDFLAGS = $(shell pkg-config --libs glib-2.0)

all:
	gcc -fPIC -shared rv_watch.c -o rv_watch.so $(CFLAGS) $(LDFLAGS)
