OBJS=algo.o field.o diffusion.o cprng.o
CFLAGS=-I ../include -fPIC -W -Wall -O2
.PHONY: build clean install

build: libssss.so

libssss.so: $(OBJS)
	$(CC) $(CFLAGS) -shared -o $@ $(OBJS) -lgmp

algo.o: algo.c
	$(CC) $(CFLAGS) -c -o $@ $<

field.o: field.c
	$(CC) $(CFLAGS) -c -o $@ $<

diffusion.o: diffusion.c
	$(CC) $(CFLAGS) -c -o $@ $<

cprng.o: cprng.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(OBJS) libssss.so
