# See LICENSE for licensing information.

PROJECT = cowlib
PROJECT_DESCRIPTION = Support library for manipulating Web protocols.
PROJECT_VERSION = 1.3.0
DEPS = mimerl
dep_mimerl = git https://github.com/benoitc/mimerl


#ERLC_OPTS += +bin_opt_info
OTP_DEPS = crypto
DIALYZER_OPTS = -Werror_handling -Wunmatched_returns
CI_OTP = OTP-18.0.3

TEST_ERLC_OPTS += +'{parse_transform, eunit_autoexport}' +'{parse_transform, horse_autoexport}'
TEST_DEPS = horse triq
dep_horse = git https://github.com/extend/horse master
dep_triq = git https://github.com/krestenkrab/triq master

include erlang.mk

.PHONY: perfs

# Performance testing.

ifeq ($(MAKECMDGOALS),perfs)
.NOTPARALLEL:
endif

perfs: test-build
	$(gen_verbose) erl -noshell -pa ebin deps/horse/ebin \
		-eval 'horse:app_perf($(PROJECT)), erlang:halt().'
