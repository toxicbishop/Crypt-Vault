/*
 * Crypt Vault — AES-256-CBC Encryption Tool (C++ Version)
 *
 * Features:
 * - AES-256-CBC file & text encryption/decryption
 * - SHA-256 password-based key derivation
 * - PKCS7 padding, random IV via Windows CryptoAPI
 * - Batch processing, file stats, SHA-256 hashing
 * - No external dependencies
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <limits>
#include <ctime>
#include <sys/stat.h>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <cstdlib>
#endif

using namespace std;

// ═══════════════════════════════════════════════════════════
// SHA-256 Implementation
// ═══════════════════════════════════════════════════════════

namespace SHA256Impl {
    typedef unsigned int uint32;
    typedef unsigned long long uint64;

    static const uint32 K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    inline uint32 rotr(uint32 x, int n) { return (x >> n) | (x << (32 - n)); }
    inline uint32 ch(uint32 x, uint32 y, uint32 z) { return (x & y) ^ (~x & z); }
    inline uint32 maj(uint32 x, uint32 y, uint32 z) { return (x & y) ^ (x & z) ^ (y & z); }
    inline uint32 sig0(uint32 x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    inline uint32 sig1(uint32 x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    inline uint32 gam0(uint32 x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    inline uint32 gam1(uint32 x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    vector<unsigned char> hash(const unsigned char* data, size_t len) {
        uint32 h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        uint64 bitlen = (uint64)len * 8;

        // Padding
        vector<unsigned char> msg(data, data + len);
        msg.push_back(0x80);
        while ((msg.size() % 64) != 56) msg.push_back(0x00);
        for (int i = 7; i >= 0; i--) msg.push_back((unsigned char)(bitlen >> (i * 8)));

        // Process blocks
        for (size_t off = 0; off < msg.size(); off += 64) {
            uint32 w[64];
            for (int i = 0; i < 16; i++)
                w[i] = ((uint32)msg[off+i*4]<<24)|((uint32)msg[off+i*4+1]<<16)|((uint32)msg[off+i*4+2]<<8)|msg[off+i*4+3];
            for (int i = 16; i < 64; i++)
                w[i] = gam1(w[i-2]) + w[i-7] + gam0(w[i-15]) + w[i-16];

            uint32 a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
            for (int i = 0; i < 64; i++) {
                uint32 t1 = hh + sig1(e) + ch(e,f,g) + K[i] + w[i];
                uint32 t2 = sig0(a) + maj(a,b,c);
                hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
            }
            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
        }
        return ch; // Non-alphanumeric chars unchanged
    }
    
    // Helper: Decrypts a single character
    char decryptChar(char ch) const {
        if (isupper(ch)) {
            return ((ch - 'A' - shift + 26) % 26) + 'A';
        } else if (islower(ch)) {
            return ((ch - 'a' - shift + 26) % 26) + 'a';
        } else if (isdigit(ch)) {
            int val = (ch - '0' - shift) % 10;
            if (val < 0) val += 10;
            return val + '0';
        }
        return ch;
    }
    
    // Helper: Decrypts character with a specific test shift (for brute force)
    char decryptCharWithShift(char ch, int s) const {
        if (isupper(ch)) {
            return ((ch - 'A' - s + 26) % 26) + 'A';
        } else if (islower(ch)) {
            return ((ch - 'a' - s + 26) % 26) + 'a';
        } else if (isdigit(ch)) {
            int val = (ch - '0' - s) % 10;
            if (val < 0) val += 10;
            return val + '0';
        }
        return ch;
    }
    
public:
    // Constructor with default shift of 3
    CaesarCipher(int s = 3) : shift(s) {}
    
    // Setter for shift value
    void setShift(int s) {
        shift = s;
    }
    
    // Encrypts source file to destination file
    bool encryptFile(const string& inputFile, const string& outputFile) {
        ifstream inFile(inputFile);  // Open for reading
        ofstream outFile(outputFile); // Open for writing
        
        if (!inFile.is_open()) {
            cerr << "\n❌ Error: Cannot open input file '" << inputFile << "'" << endl;
            return false;
        }
        
        if (!outFile.is_open()) {
            cerr << "\n❌ Error: Cannot create output file '" << outputFile << "'" << endl;
            return false;
        }
        
        char ch;
        // Process file char by char
        while (inFile.get(ch)) {
            outFile.put(encryptChar(ch));
        }
        
        inFile.close();
        outFile.close();
        return true;
    }
    
    // Decrypts source file to destination file
    bool decryptFile(const string& inputFile, const string& outputFile) {
        ifstream inFile(inputFile);
        ofstream outFile(outputFile);
        
        if (!inFile.is_open()) {
            cerr << "\n❌ Error: Cannot open input file '" << inputFile << "'" << endl;
            return false;
        }
        
        if (!outFile.is_open()) {
            cerr << "\n❌ Error: Cannot create output file '" << outputFile << "'" << endl;
            return false;
        }
        
        char ch;
        // Process file char by char using decryptChar logic
        while (inFile.get(ch)) {
            outFile.put(decryptChar(ch));
        }
        
        inFile.close();
        outFile.close();
        return true;
    }
    
    // Brute force attack: Tries all possible shifts (1-25)
    void bruteForceDecrypt(const string& inputFile) {
        ifstream inFile(inputFile);
        
        if (!inFile.is_open()) {
            cerr << "\n❌ Error: Cannot open file '" << inputFile << "'" << endl;
            return;
        }
        
        // Read entire file into string
        string content((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
        inFile.close();
        
        cout << "\n🔨 Trying all 25 possible shifts:" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl << endl;
        
        // Try every shift and print partial result
        for (int s = 1; s <= 25; s++) {
            cout << "Shift " << setw(2) << s << ": ";
            
            int charCount = 0;
            for (char ch : content) {
                if (charCount >= 60) break; // Limit preview length
                char decrypted = decryptCharWithShift(ch, s);
                if (decrypted == '\n' || decrypted == '\r') break;
                cout << decrypted;
                charCount++;
            }
            cout << endl;
        }
        
        cout << "\n💡 Tip: Look for readable text to find the correct shift!" << endl;
    }
    
    // Analyzes letter frequency (useful for cryptanalysis)
    void frequencyAnalysis(const string& inputFile) {
        ifstream file(inputFile);
        
        if (!file.is_open()) {
            cerr << "\n❌ Error: Cannot open file '" << inputFile << "'" << endl;
            return;
        }
        
        vector<int> freq(26, 0); // Vector to store counts of 26 letters
        int totalLetters = 0;
        char ch;
        
        // Count occurrences of each letter
        while (file.get(ch)) {
            if (isalpha(ch)) {
                freq[toupper(ch) - 'A']++;
                totalLetters++;
            }
        }
        file.close();
        
        if (totalLetters == 0) {
            cout << "\n⚠️  No alphabetic characters found in file." << endl;
            return;
        }
        
        cout << "\n📊 Letter Frequency Analysis:" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "Total letters: " << totalLetters << endl << endl;
        
        int maxFreq = *max_element(freq.begin(), freq.end());
        
        for (int i = 0; i < 26; i++) {
            if (freq[i] > 0) {
                char letter = 'A' + i;
                float percentage = (float)freq[i] / totalLetters * 100;
                int barLength = (int)((float)freq[i] / maxFreq * 40);
                
                cout << letter << ": " << setw(4) << freq[i] 
                     << " (" << fixed << setprecision(2) << setw(5) << percentage << "%) ";
                
                for (int j = 0; j < barLength; j++) {
                    cout << "█";
                }
                cout << endl;
            }
        }
        
        cout << "\n💡 In English, common letters are: E, T, A, O, I, N" << endl;
    }
    
    // ROT13 is a special Caesar cipher with shift 13
    bool rot13File(const string& inputFile, const string& outputFile) {
        int oldShift = shift;
        shift = 13; // Temporarily set shift to 13
        bool result = encryptFile(inputFile, outputFile);
        shift = oldShift; // Restore original shift
        return result;
    }
    
    // Encrypts a string directly (for quick text operations)
    string encryptText(const string& text) const {
        string result;
        for (char ch : text) {
            result += encryptChar(ch);
        }
        return result;
    }
    
    // Decrypts a string directly
    string decryptText(const string& text) const {
        string result;
        for (char ch : text) {
            result += decryptChar(ch);
        }
        return result;
    }
    
    // Displays file content (first 50 lines)
    void displayFileContent(const string& filename) {
        ifstream file(filename);
        
        if (!file.is_open()) {
            cerr << "\n❌ Error: Cannot open file '" << filename << "'" << endl;
            return;
        }
        
        cout << "\n📄 Content of '" << filename << "':" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        
        string line;
        int lineCount = 0;
        // Read line by line with limit
        while (getline(file, line) && lineCount < 50) {
            cout << line << endl;
            lineCount++;
        }
        
        if (!file.eof()) {
            cout << "\n... (truncated, showing first 50 lines) ..." << endl;
        }
        
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        file.close();
    }
    
    // Shows file statistics (size, counts)
    void showFileStats(const string& filename) {
        ifstream file(filename, ios::binary);
        
        if (!file.is_open()) {
            cerr << "\n❌ Error: Cannot open file '" << filename << "'" << endl;
            return;
        }
        
        // Get file size efficiently using stat
        struct stat st;
        stat(filename.c_str(), &st);
        long fileSize = st.st_size;
        
        file.seekg(0);
        int charCount = 0, letterCount = 0, numberCount = 0, lineCount = 0;
        char ch;
        
        // Scan file content for stats
        while (file.get(ch)) {
            charCount++;
            if (isalpha(ch)) letterCount++;
            if (isdigit(ch)) numberCount++;
            if (ch == '\n') lineCount++;
        }
        file.close();
        
        cout << "\n📈 File Statistics for '" << filename << "':" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "📏 File size:      " << fileSize << " bytes" << endl;
        cout << "📝 Total chars:    " << charCount << endl;
        cout << "🔤 Letters:        " << letterCount << endl;
        cout << "🔢 Numbers:        " << numberCount << endl;
        cout << "📄 Lines:          " << lineCount << endl;
    }
};

// Utility class for file path and extension operations
class FileHelper {
public:
    // Appends .enc to filename
    static string addEncExtension(const string& filename) {
        return filename + ".enc";
    }
    
    // Removes .enc from filename if present
    static string removeEncExtension(const string& filename) {
        if (filename.length() > 4 && filename.substr(filename.length() - 4) == ".enc") {
            return filename.substr(0, filename.length() - 4);
        }
        return filename;
    }
    
    // Checks if filename ends with .enc
    static bool hasEncExtension(const string& filename) {
        return filename.length() > 4 && filename.substr(filename.length() - 4) == ".enc";
    }
    
    // Checks if a file exists on disk
    static bool fileExists(const string& filename) {
        ifstream file(filename);
        return file.good();
    }
};

// Application Class: Handles User Interface and Menu Logic
class CaesarCipherApp {
private:
    CaesarCipher cipher; // Instance of the cipher logic class
    
    // Clears terminal screen based on OS
    void clearScreen() {
        #ifdef _WIN32
            system("cls");
        #else
            system("clear");
        #endif
    }
    
    void displayMenu() {
        cout << "\n";
        cout << "╔════════════════════════════════════════════════════╗" << endl;
        cout << "║                                                    ║" << endl;
        cout << "║      🔐 ENHANCED CAESAR CIPHER TOOL 🔐            ║" << endl;
        cout << "║                                                    ║" << endl;
        cout << "╚════════════════════════════════════════════════════╝" << endl << endl;
        cout << "  📝 BASIC OPERATIONS" << endl;
        cout << "  1. 🔒 Encrypt a file" << endl;
        cout << "  2. 🔓 Decrypt a file" << endl;
        cout << "  3. 🔤 Encrypt text (quick)" << endl;
        cout << "  4. 🔤 Decrypt text (quick)" << endl;
        cout << "  5. 🔨 Brute force decryption (try all shifts)" << endl << endl;
        cout << "  🔬 ANALYSIS TOOLS" << endl;
        cout << "  6. 📊 Frequency analysis" << endl;
        cout << "  7. 🔄 ROT13 encryption/decryption" << endl << endl;
        cout << "  📦 BATCH OPERATIONS" << endl;
        cout << "  8. 📂 Batch encrypt multiple files" << endl;
        cout << "  9. 📂 Batch decrypt multiple files" << endl << endl;
        cout << "  🛠️  UTILITIES" << endl;
        cout << "  10. 👁️  View file content" << endl;
        cout << "  11. 📈 File statistics" << endl;
        cout << "  12. 📚 About Caesar Cipher" << endl;
        cout << "  13. 🚪 Exit" << endl << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl << endl;
    }
    
    // Prompts user for a shift value (1-25) with validation
    int getValidShift() {
        int shift;
        while (true) {
            cout << "Enter shift value (1-25): ";
            if (cin >> shift && shift >= 1 && shift <= 25) {
                // Clear buffer after valid input
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                return shift;
            }
            // Handle invalid input (e.g. letters)
            cin.clear(); // Clear error flag
            cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Discard bad input
            cout << "❌ Invalid! Enter a number between 1 and 25." << endl;
        }
    }
    
    // Handles encyption of multiple files at once
    void batchEncrypt() {
        cout << "\n📂 BATCH ENCRYPT FILES" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        
        int numFiles;
        cout << "How many files to encrypt? ";
        if (!(cin >> numFiles) || numFiles < 1) {
            cout << "❌ Invalid number of files." << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            return;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        
        // Get shift once for all files
        cipher.setShift(getValidShift());
        
        vector<string> files(numFiles);
        for (int i = 0; i < numFiles; i++) {
            cout << "Enter filename " << (i + 1) << ": ";
            getline(cin, files[i]);
        }
        
        cout << "\n🔄 Processing files..." << endl;
        int successCount = 0;
        
        for (const auto& file : files) {
            string outFile = FileHelper::addEncExtension(file);
            
            if (FileHelper::fileExists(file)) {
                clock_t start = clock();
                if (cipher.encryptFile(file, outFile)) {
                    clock_t end = clock();
                    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
                    cout << "✅ " << file << " → " << outFile 
                         << " (" << fixed << setprecision(4) << time_spent << "s)" << endl;
                    successCount++;
                }
            } else {
                cout << "❌ " << file << " (file not found)" << endl;
            }
        }
        
        cout << "\n🎉 Batch encryption complete! " << successCount << "/" << numFiles << " files processed." << endl;
    }
    
    // Handles decryption of multiple files at once
    void batchDecrypt() {
        cout << "\n📂 BATCH DECRYPT FILES" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        
        int numFiles;
        cout << "How many files to decrypt? ";
        if (!(cin >> numFiles) || numFiles < 1) {
            cout << "❌ Invalid number of files." << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            return;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        
        cipher.setShift(getValidShift());
        
        vector<string> files(numFiles);
        for (int i = 0; i < numFiles; i++) {
            cout << "Enter filename " << (i + 1) << ": ";
            getline(cin, files[i]);
        }
        
        cout << "\n🔄 Processing files..." << endl;
        int successCount = 0;
        
        for (const auto& file : files) {
            string outFile;
            if (FileHelper::hasEncExtension(file)) {
                outFile = FileHelper::removeEncExtension(file);
            } else {
                outFile = "decrypted_" + file;
            }
            
            if (FileHelper::fileExists(file)) {
                clock_t start = clock();
                if (cipher.decryptFile(file, outFile)) {
                    clock_t end = clock();
                    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
                    cout << "✅ " << file << " → " << outFile 
                         << " (" << fixed << setprecision(4) << time_spent << "s)" << endl;
                    successCount++;
                }
            } else {
                cout << "❌ " << file << " (file not found)" << endl;
            }
        }
        
        cout << "\n🎉 Batch decryption complete! " << successCount << "/" << numFiles << " files processed." << endl;
    }
    
    void showAbout() {
        cout << "\n📚 ABOUT CAESAR CIPHER" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "\nThe Caesar Cipher is one of the simplest and oldest" << endl;
        cout << "encryption techniques. It is a substitution cipher" << endl;
        cout << "where each letter is shifted by a fixed number of" << endl;
        cout << "positions in the alphabet." << endl << endl;
        cout << "Example (shift = 3):" << endl;
        cout << "  Plain:  A B C D E F G H I J K L M" << endl;
        cout << "  Cipher: D E F G H I J K L M N O P" << endl << endl;
        cout << "  \"HELLO\" → \"KHOOR\"" << endl << endl;
        cout << "Named after Julius Caesar who used it to protect" << endl;
        cout << "military messages." << endl << endl;
        cout << "🔓 Weaknesses:" << endl;
        cout << "  • Only 25 possible keys (easily brute-forced)" << endl;
        cout << "  • Vulnerable to frequency analysis" << endl;
        cout << "  • Not secure for modern use" << endl;
    }
    
public:
    // Main application loop
    void run() {
        int choice;
        string inputFile, outputFile, text;
        
        while (true) {
            clearScreen();
            displayMenu();
            
            cout << "Enter your choice (1-13): ";
            // Input validation
            if (!(cin >> choice)) {
                cin.clear(); // Reset error flags
                cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Discard bad input
                cout << "\n❌ Invalid input! Press Enter to continue...";
                cin.get();
                continue;
            }
            cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Consume newline
            
            if (choice == 13) {
                cout << "\n👋 Thank you for using Enhanced Caesar Cipher! Goodbye!" << endl;
                break;
            }
            
            switch (choice) {
                case 1: { // Encrypt file
                    cout << "\n📝 ENCRYPT FILE" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter input filename: ";
                    getline(cin, inputFile);
                    
                    cout << "Enter output filename (or press Enter for auto): ";
                    getline(cin, outputFile);
                    
                    if (outputFile.empty()) {
                        outputFile = FileHelper::addEncExtension(inputFile);
                        cout << "Output will be: " << outputFile << endl;
                    }
                    
                    cipher.setShift(getValidShift());
                    
                    clock_t start = clock();
                    if (cipher.encryptFile(inputFile, outputFile)) {
                        clock_t end = clock();
                        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
                        cout << "\n✅ File encrypted successfully!" << endl;
                        cout << "⏱️  Time: " << fixed << setprecision(4) << time_spent << " seconds" << endl;
                        cipher.showFileStats(outputFile);
                    }
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                }
                
                case 2: { // Decrypt file
                    cout << "\n🔓 DECRYPT FILE" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter input filename: ";
                    getline(cin, inputFile);
                    
                    cout << "Enter output filename (or press Enter for auto): ";
                    getline(cin, outputFile);
                    
                    if (outputFile.empty()) {
                        if (FileHelper::hasEncExtension(inputFile)) {
                            outputFile = FileHelper::removeEncExtension(inputFile);
                        } else {
                            outputFile = "decrypted.txt";
                        }
                        cout << "Output will be: " << outputFile << endl;
                    }
                    
                    cipher.setShift(getValidShift());
                    
                    clock_t start = clock();
                    if (cipher.decryptFile(inputFile, outputFile)) {
                        clock_t end = clock();
                        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
                        cout << "\n✅ File decrypted successfully!" << endl;
                        cout << "⏱️  Time: " << fixed << setprecision(4) << time_spent << " seconds" << endl;
                        cipher.showFileStats(outputFile);
                    }
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                }
                
                case 3: // Encrypt text
                    cout << "\n🔤 ENCRYPT TEXT" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter text to encrypt: ";
                    getline(cin, text);
                    
                    cipher.setShift(getValidShift());
                    
                    cout << "\n🔒 Encrypted: " << cipher.encryptText(text) << endl;
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                case 4: // Decrypt text
                    cout << "\n🔤 DECRYPT TEXT" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter text to decrypt: ";
                    getline(cin, text);
                    
                    cipher.setShift(getValidShift());
                    
                    cout << "\n🔓 Decrypted: " << cipher.decryptText(text) << endl;
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                case 5: // Brute force
                    cout << "\n🔨 BRUTE FORCE DECRYPTION" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter encrypted filename: ";
                    getline(cin, inputFile);
                    
                    cipher.bruteForceDecrypt(inputFile);
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                case 6: // Frequency analysis
                    cout << "\n📊 FREQUENCY ANALYSIS" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter filename to analyze: ";
                    getline(cin, inputFile);
                    
                    cipher.frequencyAnalysis(inputFile);
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                case 7: // ROT13
                    cout << "\n🔄 ROT13 ENCRYPTION/DECRYPTION" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter input filename: ";
                    getline(cin, inputFile);
                    
                    cout << "Enter output filename: ";
                    getline(cin, outputFile);
                    
                    if (cipher.rot13File(inputFile, outputFile)) {
                        cout << "\n✅ ROT13 applied successfully!" << endl;
                        cipher.showFileStats(outputFile);
                    }
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                case 8: // Batch encrypt
                    batchEncrypt();
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                case 9: // Batch decrypt
                    batchDecrypt();
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                case 10: // View file
                    cout << "\n👁️  VIEW FILE CONTENT" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter filename to view: ";
                    getline(cin, inputFile);
                    
                    cipher.displayFileContent(inputFile);
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                case 11: // File statistics
                    cout << "\n📈 FILE STATISTICS" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter filename: ";
                    getline(cin, inputFile);
                    
                    cipher.showFileStats(inputFile);
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                case 12: // About
                    showAbout();
                    cout << "\nPress Enter to continue...";
                    cin.get();
                    break;
                    
                default:
                    cout << "\n❌ Invalid choice! Please select 1-13." << endl;
                    cout << "Press Enter to continue...";
                    cin.get();
            }
        }
    }
};

// Program Entry Point
int main() {
    CaesarCipherApp app; // Create application instance
    app.run();           // Start the application loop
    return 0;
}