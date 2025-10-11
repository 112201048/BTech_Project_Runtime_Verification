#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <memory>
#include <unistd.h>
#include "elfio/elfio.hpp"

using namespace std;

//Struct which holds information about a symbol
struct SymbolInfo {
    uint64_t address;
    uint64_t size;
    string type;
    string section;
};

// Function to extract required symbols from the LTL formula
vector<string> extract_required_symbols(const string ltl_formula){
    vector<string> required_symbols;
    
    // Use regex to find all potential symbols in the formula
    regex symbol_regex(R"(\b([a-zA-Z_][a-zA-Z0-9_]*)\b)");
    auto words_begin = sregex_iterator(ltl_formula.begin(), ltl_formula.end(), symbol_regex);
    auto words_end = sregex_iterator();

    // Exclude LTL keywords from the symbols
    const vector<string> ltl_keywords = {"true", "false", "U", "V", "X"};
    for (auto it = words_begin; it != words_end; ++it) {
        string symbol = it->str();
        // if symbol not in the keywords list
        if (find(ltl_keywords.begin(), ltl_keywords.end(), symbol) == ltl_keywords.end()) {
            // if not already in the required_symbols list
            if (find(required_symbols.begin(), required_symbols.end(), symbol) == required_symbols.end())
                required_symbols.push_back(symbol);
        }
    }
    return required_symbols;
}

// Pass the base address of the ELF file so that the addresses can be adjusted accordingly by adding the 
// base address to the symbol address to get the runtime virtual memory address

// Function to find addresses of required symbols from the symbol table in the ELF file
map<string, SymbolInfo> find_addresses(const string& elf_file, const vector<string>& required_symbols) {
    ELFIO::elfio reader;
    // Load ELF data
    if (!reader.load(elf_file)) {
        throw runtime_error("Could not open ELF file: " + elf_file);
    }

    // Map to hold symbol information
    map<string, SymbolInfo> symbol_map;
    
    // Iterate through sections to find symbol tables
    for (const auto& section_ptr : reader.sections) {
        // Get the current section
        ELFIO::section* section = section_ptr.get();
        // if the section is a symbol table
        if (section->get_type() == ELFIO::SHT_SYMTAB || section->get_type() == ELFIO::SHT_DYNSYM) {
            ELFIO::symbol_section_accessor symbols(reader, section);
            for (unsigned int i = 0; i < symbols.get_symbols_num(); ++i) {
                string name;
                ELFIO::Elf64_Addr value;
                ELFIO::Elf_Xword size;
                unsigned char bind;
                unsigned char type;
                ELFIO::Elf_Half section_index;
                unsigned char other;

                symbols.get_symbol(i, name, value, size, bind, type, section_index, other);
                // if name is in required_symbols
                if (find(required_symbols.begin(), required_symbols.end(), name) != required_symbols.end()) {
                    SymbolInfo info = {value, size, (type == ELFIO::STT_FUNC) ? "function" : "object", reader.sections[section_index]->get_name()};
                    symbol_map[name] = info;
                }
            }
        }
    }

    for (const auto& sym : required_symbols) {
        if (symbol_map.find(sym) == symbol_map.end()) {
            throw runtime_error("Symbol not found: " + sym);
        }
    }

    return symbol_map;
}

// Function to print the symbol information in a formatted table
void print_symbol_info(const map<string, SymbolInfo>& symbol_map) {
    cout << left << setw(20) << "Symbol" 
        << setw(20) << "Address"
        << setw(10) << "Size"
        << setw(12) << "Type"
        << "Section" << endl;
    cout << string(70, '-') << endl;

    for (const auto& [name, info] : symbol_map) {
        stringstream ss_addr;
        ss_addr << "0x" << hex << uppercase << setw(16) << setfill('0') << info.address;
        cout << left << setw(20) << name 
             << setw(20) << ss_addr.str()
             << dec << setfill(' ') 
             << setw(10) << info.size 
             << setw(12) << info.type 
             << info.section << endl;
    }
    cout << string(70, '-') << endl;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <elf_file> <ltl_formula>" << endl;
        return 1;
    }

    string elf_file = argv[1];
    string ltl_formula = argv[2];
    
    vector<string> required_symbols = extract_required_symbols(ltl_formula);
    
    // Using fork, create a child process which will have a ptrace traceme call followed by an execve call
    // The child process will be traced by the parent process
    // the child process will stop just after loading the ELF file in memory
    // at this point the ELF file is loaded in memory and the symbols are resolved
    // and the base address of the executable is known
    // The child process pauses just before executing the first instruction
    // parent was waiting for the child to stop using waitpid
    // The parent process will then read the memory mappings of the child process
    // from the /proc/<child_pid>/maps file
    // and get the base address of the executable
    // The parent process will then call the find_addresses function by passing the base address
    // of the executable and the ELF file path and the list of required symbols to get the
    // runtime virtual memory addresses of the symbols by adding the base address to the symbol address
    // The parent process will then print the symbol information in a formatted table

    
    // pid_t child_pid = fork();

    try {
        map<string, SymbolInfo> symbol_map = find_addresses(elf_file, required_symbols);
        print_symbol_info(symbol_map);
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}