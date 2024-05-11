#ifndef __DFILE_H__
#define __DFILE_H__
#include <iostream>

class dFile {  
    public:
        size_t size;
        void* memFilePtr;
        char *filename;
        void loadFile();
        size_t getLoadedSize();
        void Create(std::string filename);
        void clear();
    private:
        size_t _getFileSize();
};

#endif // __DFILE_H__