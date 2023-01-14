export VENV_PATH := .venv
TESTED_COMPILER_VERSIONS := 9.2.1 9.3.1 10.1.1 10.2.0

COMPILER_VERSION := $(shell gcc --version | grep -oP '\d+\.\d+\.\d+' | head -n1)

OPTIMIZATIONS := 0 1 2 3 fast g s
ARCHITECTURES := 32 64

CC = gcc -g0 -std=c99 -fno-stack-protector -m$$architecture -O$$optimization_level

SYSTEM_TESTS_SRC_PATH := tests/samples/src/systemtests
SYSTEM_TESTS_BIN_PATH := tests/samples/bin/systemtests
EXTENDED_TESTS_SRC_PATH := tests/samples/src/extended
EXTENDED_TESTS_BIN_PATH := tests/samples/bin/extended

system_tests_sources := $(wildcard $(SYSTEM_TESTS_SRC_PATH)/*.c)
extended_tests_sources := $(wildcard $(EXTENDED_TESTS_SRC_PATH)/*.c)

system_tests_sample_src_file_names := $(notdir $(system_tests_sources))
system_tests_sample_names := $(basename $(system_tests_sample_src_file_names))

extended_tests_sample_src_file_names := $(notdir $(extended_tests_sources))
extended_tests_sample_names := $(basename $(extended_tests_sample_src_file_names))

ALL_TEST_SAMPLES := $(wildcard tests/samples/*.c)
FULL_TEST_BINARY_PATH := tests/samples/all-samples

system_tests_binaries := $(addprefix tests/samples/systemtests/, $(SYSTEM_TESTS))


.PHONY: default
default: tests

.ONESHELL: check-format
.PHONY: check-format
ifdef CONFIG_NO_VENV
check-format:
else
check-format: venv
	. $(VENV_PATH)/bin/activate
endif
	python -m black --version
	python -m black --check .
	python -m isort --version
	python -m isort --check . -s install_api.py -s $(VENV_PATH) --skip-glob dewolf-idioms --skip-glob logic

.ONESHELL: format
.PHONY: format
ifdef CONFIG_NO_VENV
format:
else
format: venv
	. $(VENV_PATH)/bin/activate
endif
	python -m black --version
	python -m black .
	python -m isort --version
	python -m isort . -s install_api.py -s $(VENV_PATH)

.PHONY: tests
tests: unittests systemtests visualtest


.PHONY: quicktests
quicktests: unittests visualtest


.ONESHELL: systemtests
.PHONY: systemtests
ifdef CONFIG_NO_VENV
systemtests: system-tests-samples
else
systemtests: venv system-tests-samples
	. $(VENV_PATH)/bin/activate
endif
	PYTHONPATH=. pytest tests/test_plugin.py
	py.test --systemtests tests/test_sample_binaries.py

.ONESHELL: extendedtests
.PHONY: extendedtests
ifdef CONFIG_NO_VENV
extendedtests: extended-test-samples system-tests-samples
else
extendedtests: venv extended-test-samples system-tests-samples
	. $(VENV_PATH)/bin/activate
endif
	py.test --fulltests tests/test_sample_binaries.py; \

.ONESHELL: unittests
.PHONY: unittests
ifdef CONFIG_NO_VENV
unittests:
else
unittests: venv
	. $(VENV_PATH)/bin/activate
endif
	PYTHONPATH=. pytest --ignore-glob="*test-lifting.py" --ignore-glob="tests/test_sample_binaries.py" --ignore-glob="tests/test_plugin.py" tests


.PHONY: pytest
pytest: unittests

.ONESHELL: visualtest
.PHONY: visualtest
ifdef CONFIG_NO_VENV
visualtest: system-tests-samples extended-test-samples
else
visualtest: venv system-tests-samples extended-test-samples
	. $(VENV_PATH)/bin/activate
endif
	python decompile.py tests/samples/bin/systemtests/32/0/test_loop test10
	python decompile.py tests/samples/bin/systemtests/32/2/test_switch test2
	python decompile.py tests/samples/bin/systemtests/64/0/test_loop test2
	python decompile.py tests/samples/bin/systemtests/64/1/test_condition test5
	python decompile.py tests/samples/bin/systemtests/64/3/test_switch test7
	python decompile.py tests/samples/bin/systemtests/64/2/condmap main
	python decompile.py tests/samples/bin/systemtests/32/0/test_goto test2

venv:
	$(MAKE) -f Makefile.venv venv

define compile_arch_opt_combinations
    for arch in $(ARCHITECTURES); do \
		for opt in $(OPTIMIZATIONS); do \
			mkdir -p $(1)/$$arch/$$opt/
			$(MAKE) optimization_level=$$opt architecture=$$arch $(addprefix $(1)/$$arch/$$opt/, $(2)); \
		done; \
	done
endef


.PHONY: system-tests-samples
system-tests-samples: check-compiler-version
	$(call compile_arch_opt_combinations, $(SYSTEM_TESTS_BIN_PATH), $(system_tests_sample_names))


.PHONY: extended-test-samples
extended-test-samples: check-compiler-version
	$(call compile_arch_opt_combinations, $(EXTENDED_TESTS_BIN_PATH), $(extended_tests_sample_names))


$(EXTENDED_TESTS_BIN_PATH)/$(architecture)/$(optimization_level)/%: $(EXTENDED_TESTS_SRC_PATH)/%.c
	$(CC) $< -o $@
	echo $(CC) $< -o $@


$(SYSTEM_TESTS_BIN_PATH)/$(architecture)/$(optimization_level)/%: $(SYSTEM_TESTS_SRC_PATH)/%.c
	$(CC) $< -o $@
	@echo $(CC) $< -o $@


.PHONY: clean
clean: clean-samples
	$(RM) -r $(VENV_PATH)


.PHONY: clean-samples
clean-samples:
	find tests/samples/ -type f -executable -delete


.PHONY: check-compiler-version
check-compiler-version:
ifeq ($(filter $(COMPILER_VERSION), $(TESTED_COMPILER_VERSIONS)),)
	@printf "\033[31m\033[1m\033[7mThese samples have been tested for gcc versions $(TESTED_COMPILER_VERSIONS) (installed: $(COMPILER_VERSION)).
	Please consider adding your compiler version to the list of tested compiler versions and
	trying out whether make succeeds. \033[0m\n"
	@true
endif
