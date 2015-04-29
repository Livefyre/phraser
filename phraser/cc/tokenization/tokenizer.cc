#include "tokenizer.h"

#include "tokenizer_data.h"

bool Tokenizer::Init(
        const unordered_map<string, UChar>& html2unicode,
        const string& ascii_data,
        const unordered_map<UChar, uint16_t>& unicode2ascii,
        const unordered_map<string, string>& token2token) {
    html2unicode_ = html2unicode;
    ascii_data_ = ascii_data;
    unicode2ascii_ = unicode2ascii;
    token2token_ = token2token;

    max_html_length_ = 0;
    for (auto& it : html2unicode) {
        auto& html = it.first;
        if (max_html_length_ < html.size()) {
            max_html_length_ = html.size();
        }
    }

    return true;
}

bool Tokenizer::InitDefault() {
    auto& html2unicode = tokenizer_data::HTML2UNICODE;
    auto& ascii_data = tokenizer_data::ASCII_DATA;
    auto& unicode2ascii = tokenizer_data::UNICODE2ASCII;
    auto& token2token = tokenizer_data::TOKEN2TOKEN;
    return Init(html2unicode, ascii_data, unicode2ascii, token2token);
}

bool Tokenizer::ParseHTMLEntity(
        const vector<UChar>& in, size_t begin, size_t end_excl,
        UChar* out) const {
    *out = 0;
    size_t length = end_excl - begin;
    if (1 <= length && in[begin] == '#') {
        if (2 <= length && in[begin + 1] == 'x') {
            for (auto i = begin + 2; i < end_excl; ++i) {
                auto c = in[i];
                if ('0' <= c && c <= '9') {
                    c -= '0';
                } else if ('a' <= c && c <= 'z') {
                    c -= 'a';
                    c += 10;
                } else if ('A' <= c && c <= 'Z') {
                    c -= 'A';
                    c += 10;
                } else {
                    return false;
                }
                *out *= 16;
                *out += c;
            }
        } else {
            for (auto i = begin + 1; i < end_excl; ++i) {
                auto c = in[i];
                if ('0' <= c && c <= '9') {
                    c -= '0';
                } else {
                    return false;
                }
                *out *= 10;
                *out += c;
            }
        }
    } else {
        if (max_html_length_ < length) {
            return false;
        }

        string name;
        for (auto i = begin; i < end_excl; ++i) {
           auto& c = in[i];
           if ('0' <= c && c <= '9') {
               name += static_cast<char>(c);
               continue;
           } else if ('a' <= c && c <= 'z') {
               name += static_cast<char>(c);
               continue;
           } else if ('A' <= c && c <= 'Z') {
               name += static_cast<char>(c);
               continue;
           } else {
               return false;
           }
        }

        auto it = html2unicode_.find(name);
        if (it == html2unicode_.end()) {
            return false;
        }

        *out = it->second;
    }

    return true;
}

void Tokenizer::HandlePossibleHTMLEntity(
        const vector<UChar>& in, size_t amp_index, size_t semicolon_index,
        vector<UChar>* out) const {
    UChar c;
    if (ParseHTMLEntity(in, amp_index + 1, semicolon_index - 1, &c)) {
        out->emplace_back(c);
        return;
    }

    for (auto i = amp_index; i <= semicolon_index; ++i) {
        out->emplace_back(in[i]);
    }
}

bool Tokenizer::IsPossibleHTMLEntityChar(UChar c) const {
    if (c == '#') {
        return true;
    }

    if ('0' <= c && c <= '9') {
        return true;
    }

    if ('a' <= c && c <= 'z') {
        return true;
    }

    if ('A' <= c && c <= 'Z') {
        return true;
    }

    return false;
}

void Tokenizer::ReplaceHTMLEntities(
        const vector<UChar>& in, vector<UChar>* out) const {
    size_t begin = ~0ul;
    bool inside = false;
    for (auto i = 0u; i < in.size(); ++i) {
        auto& c = in[i];

        // Not inside an HTML entity.
        if (!inside) {
            if (c == '&') {
                begin = i;
                inside = true;
            } else {
                out->emplace_back(c);
            }
            continue;
        }

        // Inside an HTML entity.
        if (c == '&') {
            // Ampersand?  Reject what we buffered and start here.
            for (auto j = begin; j < i; ++j) {
                out->emplace_back(in[j]);
            }
            begin = i;
        } else if (c == ';') {
            // Semicolon?  Try to parse it (append entity or string).
            HandlePossibleHTMLEntity(in, begin, i, out);
            begin = ~0ul;
            inside = false;
        } else if (!IsPossibleHTMLEntityChar(c)) {
            // Not possible inside an HTML entity?  Reject it.
            for (auto j = begin; j <= i; ++j) {
                out->emplace_back(in[j]);
            }
            begin = ~0ul;
            inside = false;
        }
    }

    if (inside) {
        for (auto i = begin; i < in.size(); ++i) {
            out->emplace_back(in[i]);
        }
    }
}

void Tokenizer::UnicodeToPTBAscii(const vector<UChar>& in, string* out) const {
    for (auto i = 0u; i < in.size(); ++i) {
        auto it = unicode2ascii_.find(in[i]);
        if (it == unicode2ascii_.end()) {
            if (out->size() && (*out)[out->size() - 1] != ' ') {
                *out += ' ';
            }
        } else {
            auto& index = it->second;
            const auto& pointer = &ascii_data_[index];
            *out = string(pointer);
        }
    }
}

void Tokenizer::NormalizeTokens(vector<string>* tokens) const {
    for (auto i = 0u; i < tokens->size(); ++i) {
        auto& s = (*tokens)[i];
        auto it = token2token_.find(s);
        if (it != token2token_.end()) {
            s = it->second;
        }
    }
}

void Tokenizer::Tokenize(
        const vector<UChar>& text, vector<string>* tokens,
        bool replace_html_entities) const {
    // HTML -> Unicode.
    vector<UChar> processed;
    const vector<UChar>* unicode;
    if (replace_html_entities) {
        ReplaceHTMLEntities(text, &processed);
        unicode = &processed;
    } else {
        unicode = &text;
    }

    // Unicode -> ASCII.
    string ptb_ascii;
    UnicodeToPTBAscii(*unicode, &ptb_ascii);

    // ASCII -> tokens.
    ascii_tokenizer_.Tokenize(ptb_ascii, tokens);

    // Tokens -> tokens.
    NormalizeTokens(tokens);
}