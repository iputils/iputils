SGMLFILES=$(shell echo *.sgml)
HTMLFILES=$(subst .sgml,.html,$(SGMLFILES)) index.html
MANFILES=$(subst .sgml,.8,$(SGMLFILES))

all: html

html: $(HTMLFILES) iputils.html

man: $(MANFILES) fix_sgml2man

# docbook scripts are incredibly dirty in the sense that they leak
# lots of some strange temporary junk directories and files.
# So, scope it to a temporary dir and clean all after each run.

SETUP_TMPDIR = \
	t="tmp.db2html.$@"; \
	rm -rf $$t; \
	mkdir $$t; \
	pushd $$t >/dev/null
CLEAN_TMPDIR = \
	popd >/dev/null; \
	rm -rf $$t

MAKE_HTML = \
	@set -e; \
	$(SETUP_TMPDIR); \
	docbook2html ../$<; \
	mv *.html ..; \
	$(CLEAN_TMPDIR)

$(HTMLFILES): index.db
	$(MAKE_HTML)

iputils.html: iputils.db
	$(MAKE_HTML)

# docbook2man produces utterly ugly output and I did not find
# any way to customize this but hacking backend perl script a little.
# Well, hence...

$(MANFILES): index.db
	@set -e; \
	$(SETUP_TMPDIR); \
	nsgmls ../$< | sgmlspl ../docbook2man-spec.pl; \
	mv $@ ..; \
	$(CLEAN_TMPDIR)

fix_sgml2man:
	@sed -i -e 's!\\fB\\fIdestination\\fB\\fR \[\\fB/\\fIport\\fB\\fR\]!\\fB\\fIdestination\\fB\\fR[\\fB/\\fIport\\fB\\fR]!g' tracepath.8

clean:
	@rm -rf $(MANFILES) $(HTMLFILES) iputils.html tmp.db2html* tmp.db2man*

snapshot:
	@date "+%y%m%d" > snapshot.db


$(MANFILES): $(SGMLFILES)

$(HTMLFILES): $(SGMLFILES)


