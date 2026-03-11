CXX = g++
CXXFLAGS = -std=c++17 -O2 -I include
LDFLAGS = -lws2_32

SRC_DIR = src
INC_DIR = include
OBJ_DIR = .obj

# Find all cpp files in src directory
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
# Generate object file names
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

TARGET = crypt-vault.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS)

# Rule to compile cpp to obj
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Create obj directory
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR)
	rm -f $(TARGET)
