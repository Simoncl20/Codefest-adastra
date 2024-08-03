#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <cstring>

// Definiciones de constantes
const std::size_t CHUNK_SIZE_MB = 1; // Tamaño del chunk en MB
const std::string TOTP_SECRET_KEY = "your_totp_secret_key";
const int TOTP_INTERVAL = 30; // Intervalo de regeneración de la clave en segundos

// Función para inicializar el contexto de encriptación/desencriptación
bool initCipher(EVP_CIPHER_CTX*& ctx, const unsigned char* key, const unsigned char* iv, bool encrypt) {
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    if (encrypt) {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    } else {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    return true;
}

// Función para encriptar o desencriptar un chunk
std::vector<unsigned char> processChunk(const std::vector<unsigned char>& chunk, const unsigned char* key, const unsigned char* iv, bool encrypt) {
    EVP_CIPHER_CTX* ctx;
    if (!initCipher(ctx, key, iv, encrypt)) {
        std::cerr << "Error initializing encryption context" << std::endl;
        return {};
    }

    std::vector<unsigned char> processed(chunk.size() + AES_BLOCK_SIZE); // Ajustar tamaño para manejar padding
    int out_len1 = (int)processed.size();

    if (encrypt) {
        if (EVP_EncryptUpdate(ctx, processed.data(), &out_len1, chunk.data(), (int)chunk.size()) != 1) {
            std::cerr << "Error during encryption" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    } else {
        if (EVP_DecryptUpdate(ctx, processed.data(), &out_len1, chunk.data(), (int)chunk.size()) != 1) {
            std::cerr << "Error during decryption" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    }

    int out_len2 = 0;
    if (encrypt) {
        if (EVP_EncryptFinal_ex(ctx, processed.data() + out_len1, &out_len2) != 1) {
            std::cerr << "Error finalizing encryption" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    } else {
        if (EVP_DecryptFinal_ex(ctx, processed.data() + out_len1, &out_len2) != 1) {
            std::cerr << "Error finalizing decryption" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    }

    processed.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);

    return processed;
}

// Función para generar una clave con un algoritmo TOTP-like
void generateKeyTOTP(unsigned char* key, std::size_t keySize, std::time_t timestamp) {
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLength;

    HMAC(EVP_sha256(), TOTP_SECRET_KEY.data(), TOTP_SECRET_KEY.size(), reinterpret_cast<unsigned char*>(&timestamp), sizeof(timestamp), hmac, &hmacLength);

    // Copiar los primeros keySize bytes del HMAC a la llave
    std::memcpy(key, hmac, std::min(keySize, (std::size_t)hmacLength));
}

// Función para procesar y encriptar el archivo en chunks
void processFileInChunks(const std::string& inputFilePath, const std::string& outputFilePath, const unsigned char* key, const unsigned char* iv, bool encrypt) {
    std::ifstream inputFile(inputFilePath, std::ifstream::binary);
    if (!inputFile.is_open()) {
        std::cerr << "Error opening input file: " << inputFilePath << std::endl;
        return;
    }

    std::ofstream outputFile(outputFilePath, std::ofstream::binary);
    if (!outputFile.is_open()) {
        std::cerr << "Error opening output file: " << outputFilePath << std::endl;
        return;
    }

    // Escribir el IV al inicio del archivo de salida
    outputFile.write(reinterpret_cast<const char*>(iv), 16);
    if (!outputFile) {
        std::cerr << "Error writing IV to output file: " << outputFilePath << std::endl;
        return;
    }

    HMAC_CTX* hmacCtx = HMAC_CTX_new();
    HMAC_Init_ex(hmacCtx, key, 32, EVP_sha256(), NULL);

    std::vector<unsigned char> buffer(CHUNK_SIZE_MB * 1024 * 1024); // Buffer de CHUNK_SIZE_MB MB
    while (inputFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || inputFile.gcount() > 0) {
        std::streamsize bytesRead = inputFile.gcount();
        buffer.resize(bytesRead);

        // Encriptar o desencriptar el chunk leído
        std::vector<unsigned char> processedChunk = processChunk(buffer, key, iv, encrypt);
        if (processedChunk.empty()) {
            std::cerr << "Error processing chunk" << std::endl;
            HMAC_CTX_free(hmacCtx);
            return;
        }

        // Actualizar el HMAC con el chunk procesado
        HMAC_Update(hmacCtx, processedChunk.data(), processedChunk.size());

        // Escribir el chunk procesado en el archivo de salida
        outputFile.write(reinterpret_cast<const char*>(processedChunk.data()), processedChunk.size());
        if (!outputFile) {
            std::cerr << "Error writing to output file: " << outputFilePath << std::endl;
            HMAC_CTX_free(hmacCtx);
            return;
        }

        // Restaurar el tamaño del buffer original
        buffer.resize(CHUNK_SIZE_MB * 1024 * 1024);
    }

    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLength;
    HMAC_Final(hmacCtx, hmac, &hmacLength);
    HMAC_CTX_free(hmacCtx);

    // Escribir el HMAC al final del archivo de salida
    outputFile.write(reinterpret_cast<const char*>(hmac), hmacLength);
    if (!outputFile) {
        std::cerr << "Error writing HMAC to output file: " << outputFilePath << std::endl;
        return;
    }

    inputFile.close();
    outputFile.close();
}

// Función para cifrar el archivo
void encryptFile(const std::string& inputFilePath, const std::string& outputFilePath) {
    unsigned char key[32];
    unsigned char iv[16];

    // Generar IV aleatorio
    if (!RAND_bytes(iv, sizeof(iv))) {
        std::cerr << "Error generating IV" << std::endl;
        return;
    }

    // Generar clave con el timestamp actual
    std::time_t timestamp = std::time(nullptr);
    generateKeyTOTP(key, sizeof(key), timestamp);

    processFileInChunks(inputFilePath, outputFilePath, key, iv, true); // Encriptar en bloques de CHUNK_SIZE_MB MB
    std::cout << "Encryption complete. Output saved to " << outputFilePath << std::endl;
}

int main() {
    std::string inputFilePath = "/home/imagen.png";
    std::string outputFilePath = "/home/imagen_encrypted.png";

    encryptFile(inputFilePath, outputFilePath);

    return 0;
}