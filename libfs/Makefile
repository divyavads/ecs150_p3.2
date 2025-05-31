
lib := libfs.a

CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=gnu99 -g -D__USE_MISC

srcs := fs.c disk.c
objs := $(srcs:.c=.o)

all: $(lib)

$(lib): $(objs)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(lib) $(objs)

.PHONY: all clean

