#pragma once
#include <string>
#include <iostream>
#include "crypto_utils.h"
#ifdef _WIN32
#include <conio.h>
#include <io.h>
#else
#include <unistd.h>
#include <termios.h>
#endif
using namespace std;
namespace CLIUtils {
    // Helper to securely wipe string buffers
    void secureClear(string& s) {
        if (!s.empty()) {
            secure_memzero(&s[0], s.capacity());
            s.clear();
        }
    }

    // Secure password input - masks characters with asterisks
    string getSecureInput() {
        string input;
        input.reserve(256);
#ifdef _WIN32
        if (!_isatty(0)) {
            if (getline(cin, input)) {
                return input;
            }
            return "";
        }
        char ch;
        while ((ch = _getch()) != '\r' && ch != '\n') {
            if (ch == '\b' || ch == 127) {  // Backspace
                if (!input.empty()) {
                    input.pop_back();
                    cout << "\b \b" << flush;  // Erase asterisk
                }
            } else if (ch >= 32) {  // Printable characters
                input += ch;
                cout << '*' << flush;
            }
        }
        cout << endl;
#else
        if (!isatty(STDIN_FILENO)) {
            if (getline(cin, input)) {
                return input;
            }
            return "";
        }
        // POSIX: disable echo
        struct termios oldt, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ECHO | ICANON);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        
        char ch;
        while (read(STDIN_FILENO, &ch, 1) == 1 && ch != '\n' && ch != '\r') {
            if (ch == 127 || ch == '\b') {  // Backspace
                if (!input.empty()) {
                    input.pop_back();
                    cout << "\b \b" << flush;
                }
            } else if (ch >= 32) {
                input += ch;
                cout << '*' << flush;
            }
        }
        cout << endl;
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);  // Restore terminal
#endif
        return input;
    }
    string getPassword(const string& prompt = "Enter password: ") {
        cout << prompt << flush;
        string password = getSecureInput();
        
        if (password.empty()) { cout << "❌ Password cannot be empty." << endl; return ""; }
        // Password strength indicator
        int score = 0;
        if (password.length() >= 8) score++;
        if (password.length() >= 12) score++;
        bool hasUpper=false, hasLower=false, hasDigit=false, hasSpecial=false;
        for (char c : password) {
            if (isupper(c)) hasUpper=true;
            else if (islower(c)) hasLower=true;
            else if (isdigit(c)) hasDigit=true;
            else hasSpecial=true;
        }
        if (hasUpper && hasLower) score++;
        if (hasDigit) score++;
        if (hasSpecial) score++;
        string strength;
        if (score <= 1) strength = "🔴 Weak";
        else if (score <= 3) strength = "🟡 Medium";
        else strength = "🟢 Strong";
        cout << "   Password strength: " << strength << endl;
        return password;
    }
    // Password with confirmation - for encryption operations
    string getPasswordWithConfirmation() {
        string password = getPassword("Enter password: ");
        if (password.empty()) return "";
        
        cout << "Confirm password: " << flush;
        string confirm = getSecureInput();
        
        if (password != confirm) {
            cout << "❌ Passwords do not match!" << endl;
            return "";
        }
        cout << "   ✓ Passwords match" << endl;
        return password;
    }
}
