---
description: Build and test the Crypt Vault AES-256 CLI Tool
---

1. Create a `build` directory for compiling the project executable to keep the workspace clean.
   // turbo

```powershell
New-Item -ItemType Directory -Force -Path build
```

2. Compile the `Crypt-Vault.cpp` source code using the `g++` compiler. The `-ladvapi32` flag is mandatory on Windows for CryptoAPI linkages needed by the AES-256 implementation.
   // turbo

```powershell
g++ -o build/Crypt-Vault.exe Crypt-Vault.cpp -std=c++17 -Wall -Wextra -O2 -ladvapi32
```

3. Ensure the compilation was successful by checking if our executable file exists.
   // turbo

```powershell
Test-Path build/Crypt-Vault.exe
```

4. We test the executable briefly to ensure that it runs without immediate errors. We pipe '11' to instruct the interactive menu to exit immediately after launching.
   // turbo

```powershell
echo 11 | .\build\Crypt-Vault.exe
```

5. (Optional) Run the app manually and interactively using a standard terminal command.

```powershell
.\build\Crypt-Vault.exe
```
