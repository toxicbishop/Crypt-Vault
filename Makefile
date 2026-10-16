CXX ?= g++
CC ?= gcc

CXXFLAGS = -std=c++17 -O2 \
           -I include \
           -I src/vendor \
           -I src/vendor/secp256k1/include \
           -DJSON_HAS_CPP_14 \
           -D_WIN32_WINNT=0x0A00

CFLAGS = -O2 \
         -I include \
         -I src \
         -I src/vendor \
         -I src/vendor/secp256k1 \
         -I src/vendor/secp256k1/include \
         -DENABLE_MODULE_RECOVERY=1 \
         -DSECP256K1_STATIC=1

CPPFLAGS =
LDFLAGS =
LDLIBS = -lz -lssl -lcrypto

ifeq ($(OS),Windows_NT)
LDLIBS += -lws2_32 -ladvapi32 -lcrypt32 -lgdi32 -lbcrypt
endif

SRC_DIR = src
OBJ_DIR = .obj

SRCS = $(wildcard $(SRC_DIR)/*.cpp)
C_SRCS = $(wildcard $(SRC_DIR)/*.c)

OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRCS)) \
       $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.c.o,$(C_SRCS))

TARGET = crypt-vault.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) $(OBJS) -o $@ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.c.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

clean:
	-rm -rf $(OBJ_DIR)
	-rm -f $(TARGET)
	-rm -f make_output.txt gcc_v.txt check.txt find_paths.ps1 get_gcc_paths.ps1
