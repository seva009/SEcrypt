#include "textsteg.h"


std::string replaces[][2] = {{"кос", "кас"}, {"гор", "гар"}, {"стел", "стил"}, {"бер", "бир"}};

std::pair<int, std::string> hide(std::vector<bool> bits, std::string text) {
    int cur_data_index = 0;
    std::string res;
    bool added = false;
    for (int pos = 0; pos < text.size(); ++pos) {
        for (int ri = 0, added = false; cur_data_index < bits.size() && !added && ri < sizeof(replaces) / sizeof(replaces[0]); ++ri) {
            std::string zero = replaces[ri][0];
            std::string one  = replaces[ri][1];
            bool isz = text.substr(pos, zero.size()) == zero, iso = text.substr(pos, one.size()) == one;
            if (!isz && !iso) {
                continue;
            }
            added = true;
            if (bits[cur_data_index]) {
                res.append(one);
            } else {
                res.append(zero);
            }
            pos += (isz ? zero.size() : one.size()) - 1;
            cur_data_index++;
        }
        if (!added) {
            res.push_back(text[pos]);
            added = false;
        }
    }
    return {cur_data_index-1, res};
}

std::vector<bool> reveal(std::string text) {
    int cur_data_index = 0;
    std::vector<bool> res;
    for (int pos = 0; pos < text.size(); ++pos) {
        for (int ri = 0; ri < sizeof(replaces) / sizeof(replaces[0]); ++ri) {
            std::string zero = replaces[ri][0];
            std::string one  = replaces[ri][1];
            bool isz = text.substr(pos, zero.size()) == zero, iso = text.substr(pos, one.size()) == one;
            if (!isz && !iso) {
                continue;
            }
            res.push_back(iso);
        }
    }
    return res;
}

std::vector<bool> stringToVecBool(const std::string& str) {
    std::vector<bool> bits;
    for (char c : str) {
        std::bitset<8> b(c);
        for (size_t i = 0; i < 8; ++i) {
            bits.push_back(b[i]);
        }
    }
    return bits;
}

std::string vecBoolToString(const std::vector<bool>& bits) {
    std::string str;
    for (size_t i = 0; i < bits.size(); i += 8) {
        std::bitset<8> b;
        for (size_t j = 0; j < 8 && (i + j) < bits.size(); ++j) {
            b[j] = bits[i + j];
        }
        str += static_cast<char>(b.to_ulong());
    }
    return str;
}


