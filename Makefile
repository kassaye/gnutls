# Release process:
#  1. Add a news entry in news-entries (see news/entries/README)
#  2. Updated the documentation ('make web' in the gnutls source)
#  3. Type 'make'
#  4. Type 'make tweet'

WML=wml
WMLFLAGS=-DTABLE_BGCOLOR="\#e5e5e5" -DTABLE_HDCOLOR="\#ccbcbc" \
	-DTABLE_BGCOLOR2="\#e0d7d7" -DWHITE="\#ffffff" -DEMAIL=\"bugs@gnutls.org\" \
	-DSTABLE_NEXT_VER="3.2" -DSTABLE_VER="3.1" -DSTABLE_OLD_VER="3.0"
COMMON=common.wml bottom.wml head.wml rawnews.wml
OUTPUT=index.html contrib.html devel.html lists.html	\
 download.html gnutls-logo.html news.html future.html	\
 documentation.html help.html openpgp.html \
 security.html commercial.html soc.html \
 comparison.html admin/bugs.html manual/index.html

all: $(OUTPUT) news.atom
	@for i in news-entries/*.xml;do X=0; if ! test -e $$i.tweet;then X=1;fi;done;if test "$$X" = "1";then echo "There are unsubmitted news. Use 'make tweet'.";fi
#	cvs commit -m "Generated." .

.PHONY: clean manual/index.html tweet stats

all-logs:
	mkdir -p logs && cd logs && rsync -av trithemius.gnupg.org:/var/log/boa/www.gnutls.org-access* .
	rm -f logs/all.log
	cd logs && for i in `ls www.gnutls.org-access*gz|sort -r`;do zcat $$i >>all.log;done
	cd logs && cat www.gnutls.org-access >>all.log;done

stats: all-logs
	mkdir -p stats
	cut -f '2-' -d ' ' --output-delimiter=" " <logs/all.log >logs/new.log
	webalizer -c stats/webalizer.conf logs/new.log -o stats/ -Dcache.db

stats-clean:
	rm -f logs/all.log

manual/index.html: manual/index.html.bak
	@cp -f manual/index.html.bak $@

NEWS_FILES=$(shell ls news-entries/*.xml)

news.atom: $(NEWS_FILES) scripts/atom.pl
	perl scripts/atom.pl >$@

tweet: $(NEWS_FILES)
	perl scripts/tweet.pl

news.html: news.wml $(COMMON) $(NEWS_FILES)
	$(WML) $(WMLFLAGS) $< > $@.tmp
	mv $@.tmp $@

index.html: gnutls.wml $(COMMON) $(NEWS_FILES)
	$(WML) $(WMLFLAGS) $< > $@.tmp
	mv $@.tmp $@

%.html: %.wml $(COMMON)
	$(WML) $(WMLFLAGS) $< > $@.tmp
	mv $@.tmp $@

clean:
	rm -f *~ $(OUTPUT)