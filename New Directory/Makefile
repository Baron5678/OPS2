override CFLAGS=-Wall -Wextra -Wshadow -fanalyzer -g -O0 -fsanitize=address,undefined -lrt -lpthread

ifdef CI
override CFLAGS=-Wall -Wextra -Wshadow -Werror -lrt -lpthread
endif

.PHONY: clean all

all: main 

main: main.c
	gcc $(CFLAGS) -o main main.c
clean:
	rm -f main 