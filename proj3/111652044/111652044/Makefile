# 編譯器
CXX = g++

# 編譯選項
CXXFLAGS = -o crack_attack -lssl -lcrypto -lz

# 目標
TARGET = crack_attack

# 源文件
SRC = task2.cpp

# 編譯規則
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(SRC) $(CXXFLAGS)

clean:
	rm -f $(TARGET)	