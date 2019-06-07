all: generic64/libkeccak.a
generic64/libkeccak.a: bin/generic64/libkeccak.a
generic64/libkeccak.a.pack: bin/generic64_libkeccak.a.tar.gz

BINDIR = bin/.build/generic64/libkeccak.a
$(BINDIR):
	mkdir -p $(BINDIR)

MAKE ?= gmake
CC ?= gcc
AR = ar

CFLAGS := $(CFLAGS) -Ilib/high/Keccak/
CFLAGS := $(CFLAGS) -Ilib/high/Keccak/FIPS202/
CFLAGS := $(CFLAGS) -Ilib/high/Keccak/SP800-185/
CFLAGS := $(CFLAGS) -Ilib/high/common/
CFLAGS := $(CFLAGS) -Ilib/high/Keccak/PRG/
CFLAGS := $(CFLAGS) -Ilib/high/KangarooTwelve/
CFLAGS := $(CFLAGS) -Ilib/high/Kravatte/
CFLAGS := $(CFLAGS) -Ilib/common/
CFLAGS := $(CFLAGS) -fomit-frame-pointer

CFLAGS := $(CFLAGS) -O2

CFLAGS := $(CFLAGS) -g0

CFLAGS := $(CFLAGS) -march=native

CFLAGS := $(CFLAGS) -mtune=native

CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-200/Reference/
CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-400/Reference/
CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-800/Optimized32/
CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-800/Optimized32/ufull/
CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-1600/Optimized/
CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-1600/Optimized64/
CFLAGS := $(CFLAGS) -Ilib/low/common/
CFLAGS := $(CFLAGS) -m64

CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-1600/Optimized64/ufull/
CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-1600-times2/FallbackOn1/
CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-1600-times4/FallbackOn1/
CFLAGS := $(CFLAGS) -Ilib/low/KeccakP-1600-times8/FallbackOn1/
CFLAGS := $(CFLAGS) -Ilib/low/Ketje/SnP-compliant/
CFLAGS := $(CFLAGS) -Ilib/high/Ketje/
CFLAGS := $(CFLAGS) -Ilib/high/Keyak/
HEADERS := $(HEADERS) lib/high/Keccak/KeccakSponge-common.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSponge-common.h

HEADERS := $(HEADERS) lib/high/Keccak/KeccakSponge.inc
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSponge.inc

HEADERS := $(HEADERS) lib/high/Keccak/KeccakSpongeWidth200.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSpongeWidth200.h

HEADERS := $(HEADERS) lib/high/Keccak/KeccakSpongeWidth400.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSpongeWidth400.h

HEADERS := $(HEADERS) lib/high/Keccak/KeccakSpongeWidth800.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSpongeWidth800.h

HEADERS := $(HEADERS) lib/high/Keccak/KeccakSpongeWidth1600.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSpongeWidth1600.h

HEADERS := $(HEADERS) lib/high/Keccak/FIPS202/SimpleFIPS202.h
SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/SimpleFIPS202.h

HEADERS := $(HEADERS) lib/high/Keccak/FIPS202/KeccakHash.h
SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/KeccakHash.h

HEADERS := $(HEADERS) lib/high/Keccak/SP800-185/SP800-185.inc
SOURCES := $(SOURCES) lib/high/Keccak/SP800-185/SP800-185.inc

HEADERS := $(HEADERS) lib/high/Keccak/SP800-185/SP800-185.h
SOURCES := $(SOURCES) lib/high/Keccak/SP800-185/SP800-185.h

HEADERS := $(HEADERS) lib/high/common/Phases.h
SOURCES := $(SOURCES) lib/high/common/Phases.h

HEADERS := $(HEADERS) lib/high/Keccak/KeccakDuplex-common.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplex-common.h

HEADERS := $(HEADERS) lib/high/Keccak/KeccakDuplex.inc
SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplex.inc

HEADERS := $(HEADERS) lib/high/Keccak/KeccakDuplexWidth200.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplexWidth200.h

HEADERS := $(HEADERS) lib/high/Keccak/KeccakDuplexWidth400.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplexWidth400.h

HEADERS := $(HEADERS) lib/high/Keccak/KeccakDuplexWidth800.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplexWidth800.h

HEADERS := $(HEADERS) lib/high/Keccak/KeccakDuplexWidth1600.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplexWidth1600.h

HEADERS := $(HEADERS) lib/high/Keccak/PRG/KeccakPRG-common.h
SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRG-common.h

HEADERS := $(HEADERS) lib/high/Keccak/PRG/KeccakPRG.inc
SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRG.inc

HEADERS := $(HEADERS) lib/high/Keccak/PRG/KeccakPRGWidth200.h
SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRGWidth200.h

HEADERS := $(HEADERS) lib/high/Keccak/PRG/KeccakPRGWidth400.h
SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRGWidth400.h

HEADERS := $(HEADERS) lib/high/Keccak/PRG/KeccakPRGWidth800.h
SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRGWidth800.h

HEADERS := $(HEADERS) lib/high/Keccak/PRG/KeccakPRGWidth1600.h
SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRGWidth1600.h

HEADERS := $(HEADERS) lib/high/KangarooTwelve/KangarooTwelve.h
SOURCES := $(SOURCES) lib/high/KangarooTwelve/KangarooTwelve.h

HEADERS := $(HEADERS) lib/high/Kravatte/Kravatte.h
SOURCES := $(SOURCES) lib/high/Kravatte/Kravatte.h

HEADERS := $(HEADERS) lib/high/Kravatte/KravatteModes.h
SOURCES := $(SOURCES) lib/high/Kravatte/KravatteModes.h

HEADERS := $(HEADERS) lib/common/brg_endian.h
SOURCES := $(SOURCES) lib/common/brg_endian.h

HEADERS := $(HEADERS) lib/low/KeccakP-200/Reference/KeccakP-200-reference.h
SOURCES := $(SOURCES) lib/low/KeccakP-200/Reference/KeccakP-200-reference.h

HEADERS := $(HEADERS) lib/low/KeccakP-200/Reference/KeccakP-200-SnP.h
SOURCES := $(SOURCES) lib/low/KeccakP-200/Reference/KeccakP-200-SnP.h

HEADERS := $(HEADERS) lib/low/KeccakP-400/Reference/KeccakP-400-reference.h
SOURCES := $(SOURCES) lib/low/KeccakP-400/Reference/KeccakP-400-reference.h

HEADERS := $(HEADERS) lib/low/KeccakP-400/Reference/KeccakP-400-SnP.h
SOURCES := $(SOURCES) lib/low/KeccakP-400/Reference/KeccakP-400-SnP.h

HEADERS := $(HEADERS) lib/low/KeccakP-800/Optimized32/KeccakP-800-SnP.h
SOURCES := $(SOURCES) lib/low/KeccakP-800/Optimized32/KeccakP-800-SnP.h

HEADERS := $(HEADERS) lib/low/KeccakP-800/Optimized32/KeccakP-800-opt32-bis.macros
SOURCES := $(SOURCES) lib/low/KeccakP-800/Optimized32/KeccakP-800-opt32-bis.macros

HEADERS := $(HEADERS) lib/low/KeccakP-800/Optimized32/KeccakP-800-opt32.macros
SOURCES := $(SOURCES) lib/low/KeccakP-800/Optimized32/KeccakP-800-opt32.macros

HEADERS := $(HEADERS) lib/low/KeccakP-800/Optimized32/KeccakP-800-unrolling-bis.macros
SOURCES := $(SOURCES) lib/low/KeccakP-800/Optimized32/KeccakP-800-unrolling-bis.macros

HEADERS := $(HEADERS) lib/low/KeccakP-800/Optimized32/KeccakP-800-unrolling.macros
SOURCES := $(SOURCES) lib/low/KeccakP-800/Optimized32/KeccakP-800-unrolling.macros

HEADERS := $(HEADERS) lib/low/KeccakP-800/Optimized32/ufull/KeccakP-800-opt32-config.h
SOURCES := $(SOURCES) lib/low/KeccakP-800/Optimized32/ufull/KeccakP-800-opt32-config.h

HEADERS := $(HEADERS) lib/low/KeccakP-1600/Optimized/KeccakP-1600-unrolling.macros
SOURCES := $(SOURCES) lib/low/KeccakP-1600/Optimized/KeccakP-1600-unrolling.macros

HEADERS := $(HEADERS) lib/low/KeccakP-1600/Optimized/KeccakP-1600-64.macros
SOURCES := $(SOURCES) lib/low/KeccakP-1600/Optimized/KeccakP-1600-64.macros

HEADERS := $(HEADERS) lib/low/KeccakP-1600/Optimized64/KeccakP-1600-SnP.h
SOURCES := $(SOURCES) lib/low/KeccakP-1600/Optimized64/KeccakP-1600-SnP.h

HEADERS := $(HEADERS) lib/low/common/SnP-Relaned.h
SOURCES := $(SOURCES) lib/low/common/SnP-Relaned.h

HEADERS := $(HEADERS) lib/low/KeccakP-1600/Optimized64/ufull/KeccakP-1600-opt64-config.h
SOURCES := $(SOURCES) lib/low/KeccakP-1600/Optimized64/ufull/KeccakP-1600-opt64-config.h

HEADERS := $(HEADERS) lib/low/KeccakP-1600-times2/FallbackOn1/KeccakP-1600-times2-SnP.h
SOURCES := $(SOURCES) lib/low/KeccakP-1600-times2/FallbackOn1/KeccakP-1600-times2-SnP.h

HEADERS := $(HEADERS) lib/low/common/PlSnP-Fallback.inc
SOURCES := $(SOURCES) lib/low/common/PlSnP-Fallback.inc

HEADERS := $(HEADERS) lib/low/KeccakP-1600-times4/FallbackOn1/KeccakP-1600-times4-SnP.h
SOURCES := $(SOURCES) lib/low/KeccakP-1600-times4/FallbackOn1/KeccakP-1600-times4-SnP.h

HEADERS := $(HEADERS) lib/low/KeccakP-1600-times8/FallbackOn1/KeccakP-1600-times8-SnP.h
SOURCES := $(SOURCES) lib/low/KeccakP-1600-times8/FallbackOn1/KeccakP-1600-times8-SnP.h

HEADERS := $(HEADERS) lib/low/Ketje/SnP-compliant/Ket.inc
SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/Ket.inc

HEADERS := $(HEADERS) lib/low/Ketje/SnP-compliant/Ket-common.h
SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/Ket-common.h

HEADERS := $(HEADERS) lib/low/Ketje/SnP-compliant/KetJr.h
SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/KetJr.h

HEADERS := $(HEADERS) lib/low/Ketje/SnP-compliant/KetSr.h
SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/KetSr.h

HEADERS := $(HEADERS) lib/low/Ketje/SnP-compliant/KetMn.h
SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/KetMn.h

HEADERS := $(HEADERS) lib/low/Ketje/SnP-compliant/KetMj.h
SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/KetMj.h

HEADERS := $(HEADERS) lib/high/Ketje/Ketje-common.h
SOURCES := $(SOURCES) lib/high/Ketje/Ketje-common.h

HEADERS := $(HEADERS) lib/high/Ketje/Ketjev2.inc
SOURCES := $(SOURCES) lib/high/Ketje/Ketjev2.inc

HEADERS := $(HEADERS) lib/high/Ketje/KetjeJr.h
SOURCES := $(SOURCES) lib/high/Ketje/KetjeJr.h

HEADERS := $(HEADERS) lib/high/Ketje/KetjeSr.h
SOURCES := $(SOURCES) lib/high/Ketje/KetjeSr.h

HEADERS := $(HEADERS) lib/high/Ketje/KetjeMn.h
SOURCES := $(SOURCES) lib/high/Ketje/KetjeMn.h

HEADERS := $(HEADERS) lib/high/Ketje/KetjeMj.h
SOURCES := $(SOURCES) lib/high/Ketje/KetjeMj.h

HEADERS := $(HEADERS) lib/high/Ketje/Ketjev2.h
SOURCES := $(SOURCES) lib/high/Ketje/Ketjev2.h

HEADERS := $(HEADERS) lib/high/Keyak/Motorist.inc
SOURCES := $(SOURCES) lib/high/Keyak/Motorist.inc

HEADERS := $(HEADERS) lib/high/Keyak/Keyak-common.h
SOURCES := $(SOURCES) lib/high/Keyak/Keyak-common.h

HEADERS := $(HEADERS) lib/high/Keyak/Keyakv2.inc
SOURCES := $(SOURCES) lib/high/Keyak/Keyakv2.inc

HEADERS := $(HEADERS) lib/high/Keyak/RiverKeyak.h
SOURCES := $(SOURCES) lib/high/Keyak/RiverKeyak.h

HEADERS := $(HEADERS) lib/high/Keyak/LakeKeyak.h
SOURCES := $(SOURCES) lib/high/Keyak/LakeKeyak.h

HEADERS := $(HEADERS) lib/high/Keyak/SeaKeyak.h
SOURCES := $(SOURCES) lib/high/Keyak/SeaKeyak.h

HEADERS := $(HEADERS) lib/high/Keyak/OceanKeyak.h
SOURCES := $(SOURCES) lib/high/Keyak/OceanKeyak.h

HEADERS := $(HEADERS) lib/high/Keyak/LunarKeyak.h
SOURCES := $(SOURCES) lib/high/Keyak/LunarKeyak.h

HEADERS := $(HEADERS) lib/common/align.h
SOURCES := $(SOURCES) lib/common/align.h

SOURCES := $(SOURCES) lib/high/Keccak/KeccakSpongeWidth200.c
$(BINDIR)/KeccakSpongeWidth200.o: lib/high/Keccak/KeccakSpongeWidth200.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakSpongeWidth200.o

SOURCES := $(SOURCES) lib/high/Keccak/KeccakSpongeWidth400.c
$(BINDIR)/KeccakSpongeWidth400.o: lib/high/Keccak/KeccakSpongeWidth400.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakSpongeWidth400.o

SOURCES := $(SOURCES) lib/high/Keccak/KeccakSpongeWidth800.c
$(BINDIR)/KeccakSpongeWidth800.o: lib/high/Keccak/KeccakSpongeWidth800.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakSpongeWidth800.o

SOURCES := $(SOURCES) lib/high/Keccak/KeccakSpongeWidth1600.c
$(BINDIR)/KeccakSpongeWidth1600.o: lib/high/Keccak/KeccakSpongeWidth1600.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakSpongeWidth1600.o

SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/SimpleFIPS202.c
$(BINDIR)/SimpleFIPS202.o: lib/high/Keccak/FIPS202/SimpleFIPS202.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/SimpleFIPS202.o

SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/KeccakHash.c
$(BINDIR)/KeccakHash.o: lib/high/Keccak/FIPS202/KeccakHash.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakHash.o

SOURCES := $(SOURCES) lib/high/Keccak/SP800-185/SP800-185.c
$(BINDIR)/SP800-185.o: lib/high/Keccak/SP800-185/SP800-185.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/SP800-185.o

SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplexWidth200.c
$(BINDIR)/KeccakDuplexWidth200.o: lib/high/Keccak/KeccakDuplexWidth200.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakDuplexWidth200.o

SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplexWidth400.c
$(BINDIR)/KeccakDuplexWidth400.o: lib/high/Keccak/KeccakDuplexWidth400.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakDuplexWidth400.o

SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplexWidth800.c
$(BINDIR)/KeccakDuplexWidth800.o: lib/high/Keccak/KeccakDuplexWidth800.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakDuplexWidth800.o

SOURCES := $(SOURCES) lib/high/Keccak/KeccakDuplexWidth1600.c
$(BINDIR)/KeccakDuplexWidth1600.o: lib/high/Keccak/KeccakDuplexWidth1600.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakDuplexWidth1600.o

SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRGWidth200.c
$(BINDIR)/KeccakPRGWidth200.o: lib/high/Keccak/PRG/KeccakPRGWidth200.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakPRGWidth200.o

SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRGWidth400.c
$(BINDIR)/KeccakPRGWidth400.o: lib/high/Keccak/PRG/KeccakPRGWidth400.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakPRGWidth400.o

SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRGWidth800.c
$(BINDIR)/KeccakPRGWidth800.o: lib/high/Keccak/PRG/KeccakPRGWidth800.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakPRGWidth800.o

SOURCES := $(SOURCES) lib/high/Keccak/PRG/KeccakPRGWidth1600.c
$(BINDIR)/KeccakPRGWidth1600.o: lib/high/Keccak/PRG/KeccakPRGWidth1600.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakPRGWidth1600.o

SOURCES := $(SOURCES) lib/high/KangarooTwelve/KangarooTwelve.c
$(BINDIR)/KangarooTwelve.o: lib/high/KangarooTwelve/KangarooTwelve.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KangarooTwelve.o

SOURCES := $(SOURCES) lib/high/Kravatte/Kravatte.c
$(BINDIR)/Kravatte.o: lib/high/Kravatte/Kravatte.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/Kravatte.o

SOURCES := $(SOURCES) lib/high/Kravatte/KravatteModes.c
$(BINDIR)/KravatteModes.o: lib/high/Kravatte/KravatteModes.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KravatteModes.o

SOURCES := $(SOURCES) lib/low/KeccakP-200/Reference/KeccakP-200-reference.c
$(BINDIR)/KeccakP-200-reference.o: lib/low/KeccakP-200/Reference/KeccakP-200-reference.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakP-200-reference.o

SOURCES := $(SOURCES) lib/low/KeccakP-400/Reference/KeccakP-400-reference.c
$(BINDIR)/KeccakP-400-reference.o: lib/low/KeccakP-400/Reference/KeccakP-400-reference.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakP-400-reference.o

SOURCES := $(SOURCES) lib/low/KeccakP-800/Optimized32/KeccakP-800-opt32.c
$(BINDIR)/KeccakP-800-opt32.o: lib/low/KeccakP-800/Optimized32/KeccakP-800-opt32.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakP-800-opt32.o

SOURCES := $(SOURCES) lib/low/KeccakP-1600/Optimized64/KeccakP-1600-opt64.c
$(BINDIR)/KeccakP-1600-opt64.o: lib/low/KeccakP-1600/Optimized64/KeccakP-1600-opt64.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakP-1600-opt64.o

SOURCES := $(SOURCES) lib/low/KeccakP-1600-times2/FallbackOn1/KeccakP-1600-times2-on1.c
$(BINDIR)/KeccakP-1600-times2-on1.o: lib/low/KeccakP-1600-times2/FallbackOn1/KeccakP-1600-times2-on1.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakP-1600-times2-on1.o

SOURCES := $(SOURCES) lib/low/KeccakP-1600-times4/FallbackOn1/KeccakP-1600-times4-on1.c
$(BINDIR)/KeccakP-1600-times4-on1.o: lib/low/KeccakP-1600-times4/FallbackOn1/KeccakP-1600-times4-on1.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakP-1600-times4-on1.o

SOURCES := $(SOURCES) lib/low/KeccakP-1600-times8/FallbackOn1/KeccakP-1600-times8-on1.c
$(BINDIR)/KeccakP-1600-times8-on1.o: lib/low/KeccakP-1600-times8/FallbackOn1/KeccakP-1600-times8-on1.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakP-1600-times8-on1.o

SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/KetJr.c
$(BINDIR)/KetJr.o: lib/low/Ketje/SnP-compliant/KetJr.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KetJr.o

SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/KetSr.c
$(BINDIR)/KetSr.o: lib/low/Ketje/SnP-compliant/KetSr.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KetSr.o

SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/KetMn.c
$(BINDIR)/KetMn.o: lib/low/Ketje/SnP-compliant/KetMn.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KetMn.o

SOURCES := $(SOURCES) lib/low/Ketje/SnP-compliant/KetMj.c
$(BINDIR)/KetMj.o: lib/low/Ketje/SnP-compliant/KetMj.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KetMj.o

SOURCES := $(SOURCES) lib/high/Ketje/KetjeJr.c
$(BINDIR)/KetjeJr.o: lib/high/Ketje/KetjeJr.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KetjeJr.o

SOURCES := $(SOURCES) lib/high/Ketje/KetjeSr.c
$(BINDIR)/KetjeSr.o: lib/high/Ketje/KetjeSr.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KetjeSr.o

SOURCES := $(SOURCES) lib/high/Ketje/KetjeMn.c
$(BINDIR)/KetjeMn.o: lib/high/Ketje/KetjeMn.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KetjeMn.o

SOURCES := $(SOURCES) lib/high/Ketje/KetjeMj.c
$(BINDIR)/KetjeMj.o: lib/high/Ketje/KetjeMj.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KetjeMj.o

SOURCES := $(SOURCES) lib/high/Keyak/RiverKeyak.c
$(BINDIR)/RiverKeyak.o: lib/high/Keyak/RiverKeyak.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/RiverKeyak.o

SOURCES := $(SOURCES) lib/high/Keyak/LakeKeyak.c
$(BINDIR)/LakeKeyak.o: lib/high/Keyak/LakeKeyak.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/LakeKeyak.o

SOURCES := $(SOURCES) lib/high/Keyak/SeaKeyak.c
$(BINDIR)/SeaKeyak.o: lib/high/Keyak/SeaKeyak.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/SeaKeyak.o

SOURCES := $(SOURCES) lib/high/Keyak/OceanKeyak.c
$(BINDIR)/OceanKeyak.o: lib/high/Keyak/OceanKeyak.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/OceanKeyak.o

SOURCES := $(SOURCES) lib/high/Keyak/LunarKeyak.c
$(BINDIR)/LunarKeyak.o: lib/high/Keyak/LunarKeyak.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/LunarKeyak.o

bin/generic64/libkeccak.a: $(BINDIR) $(OBJECTS)
	mkdir -p $(dir $@)
	mkdir -p $@.headers
	cp -f $(HEADERS) $@.headers/
	$(AR) rcsv $@ $(OBJECTS)

bin/generic64_libkeccak.a.tar.gz: $(SOURCES)
	mkdir -p bin/.pack/generic64/libkeccak.a
	rm -rf bin/.pack/generic64/libkeccak.a/*
	cp $(SOURCES) bin/.pack/generic64/libkeccak.a/
	cd bin/.pack/ ; tar -czf ../../bin/generic64_libkeccak.a.tar.gz generic64/libkeccak.a/*

