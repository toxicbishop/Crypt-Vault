#include <iostream>
#include <vector>
#include <string>
#include "include/crypto_utils.h"

using namespace std;

int main() {
    AESCipher cipher;
    cipher.setKey("TestPassword123!");
    if (cipher.encryptFile("test_file.txt", "test_file.enc")) {
        cout << "Encrypted successfully!" << endl;
    } else {
        cout << "Encryption failed!" << endl;
        return 1;
    }
    
    if (cipher.decryptFile("test_file.enc", "test_file.dec")) {
        cout << "Decrypted successfully!" << endl;
    } else {
        cout << "Decryption failed!" << endl;
        return 1;
    }
    
    return 0;
}
