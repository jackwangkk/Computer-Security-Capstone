# 編譯器
CXX = g++

# 編譯選項
CXXFLAGS = -Wall -Wextra -O2

# 目標執行檔
TARGET = secure_random

# 原始碼檔案
SRC = secure_random.cpp

all: $(TARGET) set_permissions

# 編譯規則
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)
	chmod +x $(TARGET)

# 設置其他執行檔的權限
set_permissions:
	chmod +x ret2flag
	chmod +x password_checker
	chmod +x simple_rop
	chmod +x simple_shell
	chmod +x simple_rtos

# 清理規則
clean:
	del /f $(TARGET).exe