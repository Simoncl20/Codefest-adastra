#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <ctime>
#include <stdexcept>

const int KEY_SIZE = 32;  // 256 bits
const int IV_SIZE = 16;   // 128 bits
const int CHUNK_SIZE = 16 * 1024;  // 16 KB chunks
const int HMAC_SIZE = 32; // SHA-256 HMAC output size

const unsigned char SECRET_KEY[] = "mysecretkey"; // Change this to a secure key
const int INTERVAL_SECONDS = 30;

// Function to generate a dynamic AES key using TOTP-like algorithm
std::vector<unsigned char> generateAESKey() {
    unsigned long long timestamp = std::time(nullptr) / INTERVAL_SECONDS;
    unsigned char* hmac = HMAC(EVP_sha256(), SECRET_KEY, sizeof(SECRET_KEY) - 1, reinterpret_cast<unsigned char*>(&timestamp), sizeof(timestamp), nullptr, nullptr);
    
    std::vector<unsigned char> aesKey(hmac, hmac + KEY_SIZE);
    return aesKey;
}

std::vector<unsigned char> processChunk(EVP_CIPHER_CTX* ctx, const std::vector<unsigned char>& chunk, bool& isLastChunk) {
    std::vector<unsigned char> out(chunk.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen = 0;

    if (EVP_CipherUpdate(ctx, out.data(), &outlen, chunk.data(), chunk.size()) != 1) {
        throw std::runtime_error("Error in CipherUpdate");
    }

    out.resize(outlen);
    return out;
}

// Function to generate HMAC for a given data buffer
std::vector<unsigned char> generateHMAC(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    unsigned char* hmac = HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), nullptr, nullptr);
    return std::vector<unsigned char>(hmac, hmac + HMAC_SIZE);
}

void processFile(const std::string& inputFile, const std::string& outputFile, bool encrypt) {
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Cannot open input file");
    }

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("Cannot open output file");
    }

    unsigned char iv[IV_SIZE];
    std::vector<unsigned char> aesKey = generateAESKey();

    if (encrypt) {
        if (RAND_bytes(iv, IV_SIZE) != 1) {
            throw std::runtime_error("Error generating random IV");
        }
        outFile.write(reinterpret_cast<const char*>(iv), IV_SIZE);
    } else {
        inFile.read(reinterpret_cast<char*>(iv), IV_SIZE);
        if (!inFile) {
            throw std::runtime_error("Error reading IV from input file");
        }
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Error creating cipher context");
    }

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), nullptr, aesKey.data(), iv, encrypt ? 1 : 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error initializing cipher");
    }

    std::vector<unsigned char> chunk(CHUNK_SIZE);
    std::vector<unsigned char> encryptedData;
    
    while (inFile) {
        inFile.read(reinterpret_cast<char*>(chunk.data()), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();
        
        if (bytesRead > 0) {
            chunk.resize(bytesRead);
            bool isLastChunk = inFile.eof();
            std::vector<unsigned char> processedChunk = processChunk(ctx, chunk, isLastChunk);
            encryptedData.insert(encryptedData.end(), processedChunk.begin(), processedChunk.end());
        }
    }

    // If encrypting, append HMAC to the encrypted data
    if (encrypt) {
        std::vector<unsigned char> hmac = generateHMAC(encryptedData, aesKey);
        encryptedData.insert(encryptedData.end(), hmac.begin(), hmac.end());
    }

    // Write the final data to the output file
    outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());

    EVP_CIPHER_CTX_free(ctx);
    inFile.close();
    outFile.close();
}

void encryptFile(const std::string& inputFile, const std::string& outputFile) {
    processFile(inputFile, outputFile, true);
}

void decryptFile(const std::string& inputFile, const std::string& outputFile) {
    try {
        processFile(inputFile, outputFile, false);
    } catch (const std::exception& e) {
        std::cerr << "Decryption failed with current timestamp key: " << e.what() << std::endl;
        std::cerr << "Trying with previous interval key..." << std::endl;
        
        // Try decryption with the key from the previous interval
        unsigned long long timestamp = std::time(nullptr) / INTERVAL_SECONDS - 1;
        unsigned char* hmac = HMAC(EVP_sha256(), SECRET_KEY, sizeof(SECRET_KEY) - 1, reinterpret_cast<unsigned char*>(&timestamp), sizeof(timestamp), nullptr, nullptr);
        
        std::vector<unsigned char> previousAESKey(hmac, hmac + KEY_SIZE);
        
        std::ifstream inFile(inputFile, std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("Cannot open input file");
        }

        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("Cannot open output file");
        }

        unsigned char iv[IV_SIZE];
        inFile.read(reinterpret_cast<char*>(iv), IV_SIZE);
        if (!inFile) {
            throw std::runtime_error("Error reading IV from input file");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Error creating cipher context");
        }

        if (EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), nullptr, previousAESKey.data(), iv, 0) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error initializing cipher");
        }

        std::vector<unsigned char> chunk(CHUNK_SIZE);
        std::vector<unsigned char> decryptedData;
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(chunk.data()), CHUNK_SIZE);
            std::streamsize bytesRead = inFile.gcount();
            
            if (bytesRead > 0) {
                chunk.resize(bytesRead);
                bool isLastChunk = inFile.eof();
                std::vector<unsigned char> processedChunk = processChunk(ctx, chunk, isLastChunk);
                decryptedData.insert(decryptedData.end(), processedChunk.begin(), processedChunk.end());
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        inFile.close();

        // Verify and remove HMAC from the decrypted data
        if (decryptedData.size() >= HMAC_SIZE) {
            std::vector<unsigned char> dataWithoutHMAC(decryptedData.begin(), decryptedData.end() - HMAC_SIZE);
            std::vector<unsigned char> hmac(decryptedData.end() - HMAC_SIZE, decryptedData.end());
            std::vector<unsigned char> expectedHMAC = generateHMAC(dataWithoutHMAC, previousAESKey);

            if (hmac == expectedHMAC) {
                outFile.write(reinterpret_cast<const char*>(dataWithoutHMAC.data()), dataWithoutHMAC.size());
                std::cout << "File decrypted successfully with previous interval key." << std::endl;
            } else {
                throw std::runtime_error("HMAC verification failed with previous interval key.");
            }
        } else {
            throw std::runtime_error("File too small to contain valid HMAC.");
        }

        outFile.close();
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <input_file> <output_file>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];

    try {
        if (mode == "encrypt") {
            encryptFile(inputFile, outputFile);
            std::cout << "File encrypted successfully." << std::endl;
        } else if (mode == "decrypt") {
            decryptFile(inputFile, outputFile);
            std::cout << "File decrypted successfully." << std::endl;
        } else {
            std::cerr << "Invalid mode: " << mode << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
