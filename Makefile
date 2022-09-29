all:
	$(CC) main.cc -std=c++17 -Wno-ignored-attributes -static -s -fno-exceptions -fno-rtti -Os -flto -fdata-sections -ffunction-sections -Wl,--gc-sections -lstdc++