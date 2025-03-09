# Compiler
CC = clang

# Compiler flags
CFLAGS = -Wall -O0 -g

# Source files and executables
SRC = $(wildcard *.c)
EXEC = $(SRC:.c=)

# Default target builds all executables
all: $(EXEC)

# Pattern rule for other executables
%: %.c
	$(CC) $(CFLAGS) -o $@ $<

# Clean up generated files
clean:
	rm -f $(EXEC) *.o

# Create .gitignore, listing each executable on a new line
gitignore:
	@echo "*.o" > .gitignore
	@for exe in $(EXEC); do \
		echo "$$exe" >> .gitignore; \
	done

.PHONY: all clean gitignore
