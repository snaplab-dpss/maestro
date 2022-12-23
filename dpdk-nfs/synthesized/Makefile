SYNTHESIZED_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
MAESTRO_CC=g++ -std=c++11
MAESTRO_SRCS_DIR := $(SYNTHESIZED_DIR)/rss-config-from-lvas

Z3_INCLUDE := -I$(Z3_DIR)/build/include
R3S_INCLUDE := -I$(R3S_DIR)/include

Z3_LIB_FLAGS := -lz3 -Wl,-rpath,$(Z3_DIR)/build/lib -L$(Z3_DIR)/build/lib
R3S_LIB_FLAGS := -lr3s -Wl,-rpath,$(R3S_DIR)/builds/release/lib -L$(R3S_DIR)/builds/release/lib

KLEE_DIR := $(VIGOR_DIR)/klee
BUILD := $(SYNTHESIZED_DIR)/build/maestro

before-maestro:
	@mkdir -p $(BUILD)

maestro: before-maestro $(BUILD)/dependency.o $(BUILD)/libvig_access.o $(BUILD)/rss_config_builder.o $(BUILD)/constraint.o \
	$(BUILD)/parser.o $(BUILD)/logger.o
	$(MAESTRO_CC) $(MAESTRO_SRCS_DIR)/main.cpp \
	-o $(BUILD)/rss-config-from-lvas                	      \
	$(BUILD)/dependency.o                           	      \
	$(BUILD)/libvig_access.o                        	      \
	$(BUILD)/constraint.o                           	      \
	$(BUILD)/parser.o                               	      \
	$(BUILD)/rss_config_builder.o                   	      \
	$(BUILD)/logger.o                               	      \
	$(Z3_LIB_FLAGS) $(R3S_LIB_FLAGS)                	      \
	$(Z3_INCLUDE) $(R3S_INCLUDE)                    	      \
	-lstdc++

$(BUILD)/dependency.o: $(MAESTRO_SRCS_DIR)/dependency.cpp $(MAESTRO_SRCS_DIR)/dependency.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/dependency.cpp -o $(BUILD)/dependency.o $(R3S_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/libvig_access.o: $(MAESTRO_SRCS_DIR)/libvig_access.cpp $(MAESTRO_SRCS_DIR)/libvig_access.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/libvig_access.cpp -o $(BUILD)/libvig_access.o $(R3S_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/rss_config_builder.o: $(MAESTRO_SRCS_DIR)/rss_config_builder.cpp $(MAESTRO_SRCS_DIR)/rss_config_builder.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/rss_config_builder.cpp -o $(BUILD)/rss_config_builder.o $(R3S_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/constraint.o: $(MAESTRO_SRCS_DIR)/constraint.cpp $(MAESTRO_SRCS_DIR)/constraint.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/constraint.cpp -o $(BUILD)/constraint.o $(R3S_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/parser.o: $(MAESTRO_SRCS_DIR)/parser.cpp $(MAESTRO_SRCS_DIR)/parser.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/parser.cpp -o $(BUILD)/parser.o $(R3S_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/logger.o: $(MAESTRO_SRCS_DIR)/logger.cpp $(MAESTRO_SRCS_DIR)/logger.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/logger.cpp -o $(BUILD)/logger.o

clean-maestro:
	rm -rf $(BUILD)/*.o $(BUILD)/rss-config-from-lvas
