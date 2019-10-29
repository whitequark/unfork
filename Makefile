NAME = unfork
ALL = $(NAME)64.elf $(NAME)32.elf

.PHONY: all clean
all: $(ALL)
clean:
	rm -f $(ALL)

CXX64 ?= gcc -specs musl-gcc-64.specs
CXX32 ?= gcc -specs musl-gcc-32.specs
CXXFLAGS += -std=c++14 -fno-exceptions -Wall -Wextra \
	-pthread -static -Wl,-Ttext-segment,0x00100000 -g
CXXFLAGS64 = -m64
CXXFLAGS32 = -m32

$(NAME)64.elf: $(NAME).cc
	$(CXX64) $(CXXFLAGS64) $(CXXFLAGS) -o $@ $^

$(NAME)32.elf: $(NAME).cc
	$(CXX32) $(CXXFLAGS32) $(CXXFLAGS) -o $@ $^
