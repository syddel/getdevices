# Makefile for getdevices

CXX      ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17 -pthread
LDLIBS   ?= -pthread

TARGET   := getdevices
SRC      := getdevices.cpp
OBJ      := $(SRC:.cpp=.o)

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

.PHONY: all install uninstall clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	setcap cap_net_raw+ep $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(OBJ)
