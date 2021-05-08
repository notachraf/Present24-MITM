# Compiler
CC		= gcc
# Compiling flags
CFLAGS	= -O3 -pthread -I./include
# Linking flags
LFLAGS	= -O3 -pthread -I./include

SRCDIR	= src
LIBDIR	= include
OBJDIR	= obj
BINDIR	= bin
rm		= rm -f

SRC		:= $(wildcard $(SRCDIR)/*.c)
LIB		:= $(wildcard $(LIBDIR)/*.h)
OBJ		:= $(SRC:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
LIBO	:= obj/util.o obj/encryption.o obj/decryption.o

present24 : $(OBJ)
	@$(CC) -o bin/present24 obj/main_present24.o $(LIBO) $(LFLAGS)
	@echo "[+] Linking complete!"
	./bin/present24

mitm : $(OBJ)
	@$(CC) -o bin/mitm obj/main_mitm.o obj/mitm.o $(LIBO) $(LFLAGS)
	@echo "[+] Linking complete!"
	./bin/mitm 0x7e6359 0x411b34 0xf55c52 0x1c6195 8

$(OBJ) : $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(CC) -c $< -o $@ $(CFLAGS)
	@echo "[+] Compiled "$<" successufully!"


ZIPNAME=ELHAMIM_CHIBANI
zip:
	@$(rm) -r ${ZIPNAME}
	@$(rm) bin/*
	@$(rm) obj/*
	@mkdir ${ZIPNAME}
	@cp -r $(SRCDIR) ${ZIPNAME}
	@cp -r $(LIBDIR) ${ZIPNAME}
	@cp -r $(OBJDIR) ${ZIPNAME}
	@cp -r $(BINDIR) ${ZIPNAME}
	@cp Makefile ${ZIPNAME}
	@cp README.md ${ZIPNAME}
	@cp Explications.txt ${ZIPNAME}
	@zip -r $(ZIPNAME).zip $(ZIPNAME)
	@rm -r ${ZIPNAME}
	@ls -l ${ZIPNAME}*

.PHONY: clean
clean:
	@$(rm) bin/*
	@$(rm) obj/*
	@echo "[+] Cleanup complete!"
	@ls -l