#include "tracealloc.h"
#include <stdio.h>
//#include <unistd.h>
#include <string.h>
#include <iostream>
#include "dFile.h"

void dFile::loadFile() {
    FILE *fileF = fopen(filename, "rb");
    printf(filename, '\n');
    if (fileF == NULL) {
        throw std::runtime_error("Can't open file");
    }
    fseek(fileF, 0, SEEK_END);
    size = ftell(fileF);
    fseek(fileF, 0, SEEK_SET);
    memFilePtr = malloc(_getFileSize());
    if (memFilePtr == nullptr) {
        throw std::runtime_error("Memory allocation failed");
    }
    fread(memFilePtr, _getFileSize(), 1, fileF);
    fclose(fileF);
}

size_t dFile::getLoadedSize() {
    return _getFileSize();
}

void dFile::Create(std::string filename) {
    this->filename = (char*)calloc(filename.length() + 1, sizeof(char));
    strcpy(this->filename, filename.c_str());
}

void dFile::clear() {
    memset(memFilePtr, 0, _getFileSize());
    free(memFilePtr);
}

size_t dFile::_getFileSize() {
    return size;
}