all:
	ninja -C builddir

clean:
	ninja -C builddir clean

install:
	DESTDIR=$(DESTDIR) ninja -C builddir install

dist:
	ninja -C builddir dist

check:
	ninja -C builddir test
