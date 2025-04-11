#ifndef TEXTSTEG_H
#define TEXTSTEG_H

#include <iostream>
#include <vector>
#include <string>
#include <bitset>


std::pair<int, std::string> hide(std::vector<bool> bits, std::string text);

std::vector<bool> reveal(std::string text);

std::vector<bool> stringToVecBool(const std::string& str);

std::string vecBoolToString(const std::vector<bool>& bits);


#endif
