all:
	ninja -C builddir

install:
	DESTDIR=$(DESTDIR) ninja -C builddir install
