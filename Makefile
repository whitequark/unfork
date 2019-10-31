NAME = unfork
ALL = $(NAME)64.elf $(NAME)32.elf

.PHONY: all clean
all: $(ALL)
clean:
	rm -f $(ALL)

CXXFLAGS = -std=c++14 -fno-exceptions -Wall -Wextra -g
LDFLAGS  = -pthread -static -Wl,-Ttext-segment,0x00100000

$(NAME)64.elf: unfork.cc agent.cc
	gcc -specs musl-gcc-64.specs -m64 $(CXXFLAGS) $(LDFLAGS) -o $@ $^

$(NAME)32.elf: unfork.cc agent.cc
	gcc -specs musl-gcc-32.specs -m32 $(CXXFLAGS) $(LDFLAGS) -o $@ $^
