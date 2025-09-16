APP_NAME := proxychecker

CXX := g++
CXXFLAGS := -std=gnu++20 -O3 -pipe -flto -march=native -mtune=native -fno-omit-frame-pointer -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion -Wno-unused-parameter
LDFLAGS := -pthread -flto

SRC_DIR := src
BUILD_DIR := build

SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean format

all: $(APP_NAME)

$(APP_NAME): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) $(APP_NAME)

format:
	@command -v clang-format >/dev/null 2>&1 && clang-format -i $(SRCS) || echo "clang-format not found; skipping"

