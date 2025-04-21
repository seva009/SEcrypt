#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

std::string to_c_string_literal(const std::string& text) {
    std::string result;
    for (char c : text) {
        switch (c) {
        case '\n':
            result += "\\n\"\n\"";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\"':
            result += "\\\"";
            break;
        case '\\':
            result += "\\\\";
            break;
        default:
            if (isprint(static_cast<unsigned char>(c))) {
                result += c;
            }
            else {
                char buffer[5];
                snprintf(buffer, sizeof(buffer), "\\x%02X", static_cast<unsigned char>(c));
                result += buffer;
            }
            break;
        }
    }
    return result;
}

int main() {
    const char* input_filename = "index.html";
    const char* output_filename = "header.h";
    std::ifstream input_file(input_filename, std::ios::binary);
    if (!input_file) {
        std::cerr << "Error while opening -> " << input_filename << std::endl;
        return 1;
    }
    std::stringstream buffer;
    buffer << input_file.rdbuf();
    std::string file_content = buffer.str();
    std::string c_string = to_c_string_literal(file_content);
    std::ofstream output_file(output_filename);
    if (!output_file) {
        std::cerr << "Error while creating -> " << output_filename << std::endl;
        return 1;
    }
    output_file << "#ifndef HEADER_H\n";
    output_file << "#define HEADER_H\n\n";
    output_file << "const char index_html[] =\n\""
        << c_string
        << "\";\n\n";
    output_file << "#endif // HEADER_H\n";
    std::cout << "File " << output_filename << " created" << std::endl;
    return 0;
}
