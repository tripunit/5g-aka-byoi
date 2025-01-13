
M4 ?= m4

THEORIES =              \
    thy/byoi_stg1.spthy \
    thy/andrews.spthy

.PHONY: all
all: $(THEORIES)

thy/%.spthy: src/%.spthy
	cp $< $@

thy/%.spthy: src/%.spthy.m4
	$(M4) $< > $@
