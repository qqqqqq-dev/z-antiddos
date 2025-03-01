g++ -shared "%~dp0ZServerInterface.cpp" -o "%~dp0ZServerInterface.dll" -static-libgcc -static-libstdc++ -mwindows -Wl,--exclude-all-symbols -s -O2 -lole32 -loleaut32 -luuid || pause
