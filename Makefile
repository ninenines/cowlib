# See LICENSE for licensing information.

PROJECT = cowlib
CT_SUITES = eunit

include erlang.mk

GEN_URL = http://svn.apache.org/repos/asf/httpd/httpd/trunk/docs/conf/mime.types
GEN_SRC = src/cow_mimetypes.erl.src
GEN_OUT = src/cow_mimetypes.erl

gen:
	$(gen_verbose) cat $(GEN_SRC) \
		| head -n `grep -n "%% GENERATED" $(GEN_SRC) | cut -d : -f 1` \
		> $(GEN_OUT)
	$(gen_verbose) wget -qO - $(GEN_URL) \
		| grep -v ^# \
		| awk '{for (i=2; i<=NF; i++) if ($$i != "") \
			print "all_ext(<<\"" $$i "\">>) -> <<\"" $$1 "\">>;"}' \
		| sort \
		| uniq -w 25 \
		>> $(GEN_OUT)
	$(gen_verbose) cat $(GEN_SRC) \
		| tail -n +`grep -n "%% GENERATED" $(GEN_SRC) | cut -d : -f 1` \
		>> $(GEN_OUT)
