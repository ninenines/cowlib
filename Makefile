# See LICENSE for licensing information.

PROJECT = cowlib
#ERLC_OPTS += +bin_opt_info
TEST_ERLC_OPTS += +'{parse_transform, eunit_autoexport}' +'{parse_transform, horse_autoexport}'
PLT_APPS = crypto

TEST_DEPS = triq
dep_triq = git https://github.com/krestenkrab/triq master

include erlang.mk

.PHONY: gen perfs

# Mimetypes module generator.

GEN_URL = http://svn.apache.org/repos/asf/httpd/httpd/trunk/docs/conf/mime.types
GEN_SRC = src/cow_mimetypes.erl.src
GEN_OUT = src/cow_mimetypes.erl

gen:
	$(gen_verbose) cat $(GEN_SRC) \
		| head -n `grep -n "%% GENERATED" $(GEN_SRC) | cut -d : -f 1` \
		> $(GEN_OUT)
	$(gen_verbose) wget -qO - $(GEN_URL) \
		| grep -v ^# \
		| awk '{for (i=2; i<=NF; i++) if ($$i != "") { \
			split($$1, a, "/"); \
			print "all_ext(<<\"" $$i "\">>) -> {<<\"" \
				a[1] "\">>, <<\"" a[2] "\">>, []};"}}' \
		| sort \
		| uniq -w 25 \
		>> $(GEN_OUT)
	$(gen_verbose) cat $(GEN_SRC) \
		| tail -n +`grep -n "%% GENERATED" $(GEN_SRC) | cut -d : -f 1` \
		>> $(GEN_OUT)

# Performance testing.

ifeq ($(MAKECMDGOALS),perfs)
.NOTPARALLEL:
endif

deps/horse:
	git clone -n -- https://github.com/extend/horse $(DEPS_DIR)/horse
	cd $(DEPS_DIR)/horse ; git checkout -q master
	$(MAKE) -C $(DEPS_DIR)/horse

perfs: test-build
	$(gen_verbose) erl -noshell -pa ebin deps/horse/ebin \
		-eval 'horse:app_perf($(PROJECT)), erlang:halt().'
