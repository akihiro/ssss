.PHONY: build clean install

build:
	$(MAKE) -C src/ $@

install: src/libssss.so include/ssss.h
	install -o root -g root -m 755 src/libssss.so /usr/local/lib
	install -o root -g root -m 644 include/ssss.h /usr/local/include

clean:
	$(MAKE) -C src/ $@
