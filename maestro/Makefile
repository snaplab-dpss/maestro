SYNTHESIZED_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
MAESTRO_CC=c++ -std=c++11
MAESTRO_SRCS_DIR := $(SYNTHESIZED_DIR)/rss-config-from-lvas

Z3_INCLUDE := -I$(Z3_DIR)/build/include
RS3_INCLUDE := -I$(RS3_DIR)/include

Z3_LIB_FLAGS := -lz3 -Wl,-rpath,$(Z3_DIR)/build/lib -L$(Z3_DIR)/build/lib
RS3_LIB_FLAGS := -lrs3 -Wl,-rpath,$(RS3_DIR)/build/libs -L$(RS3_DIR)/build/libs
# RS3_LIB_FLAGS := -lrs3d -Wl,-rpath,$(RS3_DIR)/build/libs -L$(RS3_DIR)/build/libs

BUILD := $(SYNTHESIZED_DIR)/build/maestro

all: before-maestro $(BUILD)/dependency.o $(BUILD)/lib_access.o $(BUILD)/rss_config_builder.o $(BUILD)/constraint.o \
	$(BUILD)/parser.o $(BUILD)/logger.o
	$(MAESTRO_CC) $(MAESTRO_SRCS_DIR)/main.cpp \
	-o $(BUILD)/rss-config-from-lvas           \
	$(BUILD)/dependency.o                      \
	$(BUILD)/lib_access.o                      \
	$(BUILD)/constraint.o                      \
	$(BUILD)/parser.o                          \
	$(BUILD)/rss_config_builder.o              \
	$(BUILD)/logger.o                          \
	$(Z3_LIB_FLAGS) $(RS3_LIB_FLAGS)           \
	$(Z3_INCLUDE) $(RS3_INCLUDE)               \
	-lstdc++

$(BUILD)/dependency.o: $(MAESTRO_SRCS_DIR)/dependency.cpp $(MAESTRO_SRCS_DIR)/dependency.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/dependency.cpp -o $(BUILD)/dependency.o $(RS3_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/lib_access.o: $(MAESTRO_SRCS_DIR)/lib_access.cpp $(MAESTRO_SRCS_DIR)/lib_access.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/lib_access.cpp -o $(BUILD)/lib_access.o $(RS3_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/rss_config_builder.o: $(MAESTRO_SRCS_DIR)/rss_config_builder.cpp $(MAESTRO_SRCS_DIR)/rss_config_builder.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/rss_config_builder.cpp -o $(BUILD)/rss_config_builder.o $(RS3_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/constraint.o: $(MAESTRO_SRCS_DIR)/constraint.cpp $(MAESTRO_SRCS_DIR)/constraint.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/constraint.cpp -o $(BUILD)/constraint.o $(RS3_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/parser.o: $(MAESTRO_SRCS_DIR)/parser.cpp $(MAESTRO_SRCS_DIR)/parser.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/parser.cpp -o $(BUILD)/parser.o $(RS3_INCLUDE) $(Z3_INCLUDE)

$(BUILD)/logger.o: $(MAESTRO_SRCS_DIR)/logger.cpp $(MAESTRO_SRCS_DIR)/logger.h
	$(MAESTRO_CC) -c $(MAESTRO_SRCS_DIR)/logger.cpp -o $(BUILD)/logger.o

before-maestro:
	@mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)/*.o $(BUILD)/rss-config-from-lvas
