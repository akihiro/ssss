OBJS=cprng.o
CFLAGS=-I ../include -fPIC -W -Wall -O2
.PHONY: build clean install

build: libssss.so

libssss.so: $(OBJS)
	$(CC) $(CFLAGS) -shared -o $@ $(OBJS) -lgmp

cprng.o: cprng.c
	$(CC) $(CFLAGS) -c -o $@ $<

install:

clean:
	$(RM) $(OBJS) libssss.so
