#include <iostream>
#include <string>
#include <vector>

#include "cc/analysis/analysis_options.h"
#include "cc/analysis/analysis_result.h"
#include "cc/analysis/analyzer.h"
#include "cc/base/files.h"

using std::cin;
using std::getline;
using std::string;
using std::vector;

#define RED "\033[1;31m"
#define RESET "\033[0m"

static void OutputError(const string& error) {
    printf(RED "Failed: %s\n" RESET, error.data());
}

#undef RESET
#undef RED

// TODO: ASCII, lol
void UnicodeFromBytes(const string& in, ustring* out) {
    out->resize(in.size());
    for (auto i = 0ul; i < in.size(); ++i) {
        (*out)[i] = in[i];
    }
}

void BytesFromUnicode(const ustring& in, string* out) {
    out->resize(in.size());
    for (auto i = 0ul; i < in.size(); ++i) {
        auto c = in[i];
        if (128 <= c) {
            c = '.';
        }
        (*out)[i] = c;
    }
}

void OutputResult(const AnalysisResult& r) {
    printf("\n");
    string s;
    BytesFromUnicode(r.original_text, &s);
    printf("    original_text: %s\n", s.c_str());
    BytesFromUnicode(r.clean_text, &s);
    printf("    clean_text:    %s\n", s.c_str());
    printf("    chr2drop: {\n");
    for (auto it = r.chr2drop.begin(); it != r.chr2drop.end(); ++it) {
        printf("        %c: %lu\n", it->first, it->second);
    }
    printf("    }\n");
    printf("    tokens:");
    for (auto& s : r.tokens) {
        printf(" [%s]", s.c_str());
    }
    printf("\n");
    printf("    phrase_results: [\n");
    for (auto& pdr : r.phrase_results) {
        printf("        type: %s\n", pdr.phrase_name.c_str());
        printf("        matches: [\n");
        for (auto& m : pdr.matches) {
            printf("            match: {\n");
            for (auto i = 0ul; i < m.piece_begin_indexes.size(); ++i) {
                auto begin = m.piece_begin_indexes[i];
                auto end = begin;
                if (i != m.piece_begin_indexes.size() - 1) {
                    end = m.piece_begin_indexes[i + 1];
                } else {
                    end = m.end_excl;
                }
                printf("                %s:", pdr.piece_names[i].c_str());
                for (auto j = begin; j < end; ++j) {
                    printf(" [%s]", r.tokens[j].c_str());
                }
                printf(" from %zu to %zu\n", begin, end - 1);
            }
            printf("            }\n");
        }
        printf("\n");
    }
    printf("    ]\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    vector<string> config_files = {
        "phraser/config/threat_command.txt",
        "phraser/config/threat_statement.txt",
    };

    string error;
    vector<string> config_texts;
    for (auto& f : config_files) {
        string s;
        if (!files::FileToString(f, &s)) {
            error = "File DNE: " + f;
            OutputError(error);
            return 1;
        }
        config_texts.emplace_back(s);
    }

    Analyzer anal;
    if (!anal.Init(config_texts, &error)) {
        OutputError(error);
        return 2;
    }

    string line;
    AnalysisOptions options;
    AnalysisResult result;
    while (getline(cin, line)) {
        ustring text;
        UnicodeFromBytes(line, &text);
        if (!anal.Analyze(text, options, &result, &error)) {
            OutputError(error);
            return 3;
        }

        OutputResult(result);
    }
}
