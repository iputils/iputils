TARGETS_MAN =  arping.8 clockdiff.8 ninfod.8 pg3.8 ping.8 rarpd.8 rdisc.8 tftpd.8 tracepath.8 traceroute6.8
TARGETS_HTML =  arping.html clockdiff.html ninfod.html pg3.html ping.html rarpd.html rdisc.html tftpd.html tracepath.html traceroute6.html

IPUTILS_VERSION = s$(shell sed 's/[^0-9]*//g' ../SNAPSHOT.h)

XSLTPROC = /usr/bin/xsltproc
XSLTPROC_FLAGS = --nonet --xinclude --stringparam man.output-quietly 1 --stringparam funcsynopsis.style ansi --stringparam man.authors.section.enabled 0 --stringparam iputils.version $(IPUTILS_VERSION)

XSL_MAN = custom-man.xsl
XSL_HTML = custom-html.xsl

%.html: %.xml $(XSL_HTML)
	@$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) $(XSL_HTML) $<
%.8: %.xml $(XSL_MAN)
	@$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) $(XSL_MAN) $<

all: $(TARGETS_HTML) $(TARGETS_MAN)

man: $(TARGETS_MAN)
html: $(TARGETS_HTML)


clean:
	@rm -f *.html
	@rm -f *.8

