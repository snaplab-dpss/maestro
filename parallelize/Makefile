CC=g++

Z3_DIR=$(VIGOR_DIR)/z3
R3S_DIR=$(VIGOR_DIR)/libr3s

Z3_LIB_FLAGS=-lz3 -Wl,-rpath,$(Z3_DIR)/build/lib -L$(Z3_DIR)/build/lib -I$(Z3_DIR)/build/include
R3S_LIB_FLAGS=-lr3s -Wl,-rpath,$(R3S_DIR)/build/lib -L$(R3S_DIR)/build/lib -I$(R3S_DIR)/include

NF_DIR=$(shell pwd)
SRC=$(NF_DIR)/../parallelize
BUILD=$(NF_DIR)/build/parallelization
KLEE_DIR=$(VIGOR_DIR)/klee

all: $(BUILD)/libvig_access.o $(BUILD)/constraint.o $(BUILD)/parser.o
	$(CC) $(SRC)/parse-libvig-access.c  \
		-o $(BUILD)/parse-libvig-access \
		$(BUILD)/libvig_access.o        \
		$(BUILD)/constraint.o           \
		$(BUILD)/parser.o        \
		$(Z3_LIB_FLAGS) $(R3S_LIB_FLAGS)

$(BUILD)/libvig_access.o: $(SRC)/libvig_access.c
	$(CC) -c $(SRC)/libvig_access.c -o $(BUILD)/libvig_access.o $(Z3_LIB_FLAGS) $(R3S_LIB_FLAGS)

$(BUILD)/constraint.o: $(SRC)/constraint.c
	$(CC) -c $(SRC)/constraint.c -o $(BUILD)/constraint.o $(Z3_LIB_FLAGS) $(R3S_LIB_FLAGS)

$(BUILD)/parser.o: $(SRC)/parser.c
	$(CC) -c $(SRC)/parser.c -o $(BUILD)/parser.o $(Z3_LIB_FLAGS) $(R3S_LIB_FLAGS)

clean:
	rm -rf $(BUILD)/*.o $(BUILD)/parse-libvig-access