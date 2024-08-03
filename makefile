# Nombre del binario
TARGET = file_encrypt_decrypt

# Compilador
CXX = g++

# Archivos fuente
SRC = file_encrypt_decrypt.cpp

# Flags de enlace
LDFLAGS = -lssl -lcrypto

# Regla por defecto
all: $(TARGET)

# Regla para crear el binario
$(TARGET): $(SRC)
	$(CXX) -o $@ $^ $(LDFLAGS)

# Regla para limpiar archivos generados
clean:
	rm -f $(TARGET)

.PHONY: all clean