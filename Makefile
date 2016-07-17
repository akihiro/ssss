OBJS=ssss.o cprng.o diffusion.o
CFLAGS=-W -Wall -O2
.PHONY: all compile doc clean install

all: compile doc

compile: ssss-split ssss-combine

doc: ssss.1 ssss.1.html

ssss-split: $(OBJS)
	$(CC) $(CFLAGS) -o ssss-split $(OBJS) -lgmp
	strip ssss-split

ssss-combine: ssss-split
	ln -f ssss-split ssss-combine

ssss.1: ssss.manpage.xml
	if [ `which xmltoman` ]; then xmltoman ssss.manpage.xml > ssss.1; else echo "WARNING: xmltoman not found, skipping generate of man page."; fi
	if [ -e ssss.1 ]; then cp ssss.1 ssss-split.1; cp ssss.1 ssss-combine.1; fi

ssss.1.html: ssss.manpage.xml
	if [ `which xmlmantohtml` ]; then xmlmantohtml ssss.manpage.xml > ssss.1.html; else echo "WARNING: xmlmantohtml not found, skipping generation of HTML documentation."; fi

clean:
	rm -rf ssss-split ssss-combine ssss.1 ssss-split.1 ssss-combine.1 ssss.1.html $(OBJS)

install:
	if [ -e ssss.1 ]; then install -o root -g wheel -m 644 ssss.1 ssss-split.1 ssss-combine.1 /usr/share/man/man1; else echo "WARNING: No man page was generated, so none will be installed."; fi
	install -o root -g wheel -m 755 ssss-split ssss-combine /usr/bin

ssss.o: ssss.c ssss.h cprng.h field.h diffusion.h
	$(CC) $(CFLAGS) -c -o $@ $<

cprng.o: cprng.c
	$(CC) $(CFLAGS) -c -o $@ $<

diffusion.o: diffusion.c field.h
	$(CC) $(CFLAGS) -c -o $@ $<
