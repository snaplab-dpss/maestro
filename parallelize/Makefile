CC=clang++ -std=c++11 -stdlib=libstdc++

Z3_INCLUDE=-I$(Z3_DIR)/build/include
R3S_INCLUDE=-I$(R3S_DIR)/include

Z3_LIB_FLAGS=-lz3 -Wl,-rpath,$(Z3_DIR)/build/lib -L$(Z3_DIR)/build/lib
#R3S_LIB_FLAGS=-lr3s -Wl,-rpath,$(R3S_DIR)/build/lib -L$(R3S_DIR)/build/lib
R3S_LIB_FLAGS=-lr3sd -Wl,-rpath,$(R3S_DIR)/debug/lib -L$(R3S_DIR)/debug/lib

NF_DIR=$(shell pwd)
SRC=$(NF_DIR)/../parallelize
BUILD=$(NF_DIR)/build/parallelization
KLEE_DIR=$(VIGOR_DIR)/klee

all: $(BUILD)/libvig_access.o $(BUILD)/rss_config_builder.o $(BUILD)/constraint.o $(BUILD)/parser.o $(BUILD)/logger.o
	$(CC) $(SRC)/parse-libvig-access.cpp  	\
		-o $(BUILD)/parse-libvig-access 	\
		$(BUILD)/libvig_access.o        	\
		$(BUILD)/constraint.o           	\
		$(BUILD)/parser.o        			\
		$(BUILD)/rss_config_builder.o 		\
		$(BUILD)/logger.o			 		\
		$(Z3_LIB_FLAGS) $(R3S_LIB_FLAGS)	\
		$(Z3_INCLUDE) $(R3S_INCLUDE)		\
		-lstdc++

$(BUILD)/libvig_access.o: $(SRC)/libvig_access.cpp $(SRC)/libvig_access.h
	$(CC) -c $(SRC)/libvig_access.cpp -o $(BUILD)/libvig_access.o $(R3S_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/rss_config_builder.o: $(SRC)/rss_config_builder.cpp $(SRC)/rss_config_builder.h
	$(CC) -c $(SRC)/rss_config_builder.cpp -o $(BUILD)/rss_config_builder.o $(R3S_INCLUDE) $(Z3_INCLUDE)
	
$(BUILD)/constraint.o: $(SRC)/constraint.cpp $(SRC)/constraint.h
	$(CC) -c $(SRC)/constraint.cpp -o $(BUILD)/constraint.o $(R3S_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/parser.o: $(SRC)/parser.cpp $(SRC)/parser.h
	$(CC) -c $(SRC)/parser.cpp -o $(BUILD)/parser.o $(R3S_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/logger.o: $(SRC)/logger.cpp $(SRC)/logger.h
	$(CC) -c $(SRC)/logger.cpp -o $(BUILD)/logger.o

clean:
	rm -rf $(BUILD)/*.o $(BUILD)/parse-libvig-access
