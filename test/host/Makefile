# Host unit tests for the pure (ESP-free) sources.
#
#   make          build and run everything
#
# Sources under test are compiled straight out of the components; stubs/
# provides the ESP/lwIP headers they reference.
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Werror -std=c11 -g
ROOT    := ../..

INC := -Istubs \
       -I$(ROOT)/components/mp_core/include \
       -I$(ROOT)/components/mp_log/include \
       -I$(ROOT)/components/mp_http_ui/include \
       -I$(ROOT)/components/mp_linekit/include \
       -I$(ROOT)/components/mp_stack419/include \
       -I$(ROOT)/components/mp_stack419

TESTS := test_evt test_form test_linekit test_s419pkt

all: run

test_evt: test_evt.c $(ROOT)/components/mp_log/mp_evt.c test_util.h
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(ROOT)/components/mp_log/mp_evt.c

test_form: test_form.c $(ROOT)/components/mp_http_ui/mp_form.c test_util.h
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(ROOT)/components/mp_http_ui/mp_form.c

test_linekit: test_linekit.c $(ROOT)/components/mp_linekit/mp_linekit.c test_util.h
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(ROOT)/components/mp_linekit/mp_linekit.c

test_s419pkt: test_s419pkt.c $(ROOT)/components/mp_stack419/s419_pkt.c test_util.h
	$(CC) $(CFLAGS) -Wno-unused-parameter -Wno-unused-function $(INC) \
	    -o $@ $< $(ROOT)/components/mp_stack419/s419_pkt.c

run: $(TESTS)
	@status=0; \
	for t in $(TESTS); do ./$$t || status=1; done; \
	if [ $$status -eq 0 ]; then echo "ALL HOST TESTS PASSED"; else echo "HOST TESTS FAILED"; fi; \
	exit $$status

clean:
	rm -f $(TESTS)

.PHONY: all run clean
