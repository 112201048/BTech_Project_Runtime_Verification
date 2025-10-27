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
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/wait.h>
#include <fstream>
#include <sys/prctl.h> 
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

// Function to find addresses of required symbols from the symbol table in the ELF file and adjust them with base address
map<string, SymbolInfo> find_addresses(const string& elf_file, const vector<string>& required_symbols, uint64_t base_address) {
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
                    // Add base_address to value to get runtime virtual memory address
                    uint64_t runtime_addr = value + base_address;
                    SymbolInfo info = {runtime_addr, size, (type == ELFIO::STT_FUNC) ? "function" : "object", reader.sections[section_index]->get_name()};
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

/// @brief Function to add the offset of base_address to the value in the symbol map
/// @param symbol_map 
/// @param base_address 
/// @return updated symbol_map
map<string, SymbolInfo> update_with_base_address(map<string, SymbolInfo>& symbol_map ,uint64_t base_address) {
    for (auto& i: symbol_map) {
        i.second.address += base_address;
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

    // Find addresses without making adjustments with the base address
    map<string, SymbolInfo> symbol_map = find_addresses(elf_file, required_symbols, uint64_t(0));

    // Printing the symbol table before offset
    // print_symbol_info(symbol_map);

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

    pid_t pid = fork();
    
    if (pid == 0) {

        // Signals when the parent dies
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        // Child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        const char* argv_exec[] = {elf_file.c_str(), nullptr};
        const char* envp_exec[] = {nullptr};

        execve(elf_file.c_str(), (char* const*) argv_exec, (char* const*)envp_exec);
        perror("execve failed...\n");
        _exit(errno);

    } else if (pid > 0) {

        // Parent process
        try {

            int status;
            waitpid(pid, &status, 0);
            uint64_t base_address;

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                string map_path = "/proc/" + to_string(pid) + "/maps";
                ifstream maps_file(map_path);

                if (!maps_file.is_open()) {
                    throw runtime_error("Could not open maps file: " + map_path);
                }

                string line;
                if (getline(maps_file, line)){
                    stringstream ss(line);
                    string address_range;
                    ss >> address_range;
                    size_t dash_pos = address_range.find('-');
                    string base_str = address_range.substr(0, dash_pos);
                    base_address = stoull(base_str, nullptr, 16);
                    cout << "Base address of the executable: 0x" << hex << base_address << dec << endl;
                }
                
                // Update the symbol table with runtime addresses
                symbol_map = update_with_base_address(symbol_map, base_address);
                print_symbol_info(symbol_map);

                cout << "pid of the child process: " << pid << endl;
                cout << "Press Enter to continue execution of the child process..." << endl;
                cin.get();

                ptrace(PTRACE_CONT, pid, NULL, NULL);
                
                // Parent waits for the child to finish
                waitpid(pid, &status, 0);
            }
        } catch (const exception& e) {

            cerr << "Error: " << e.what() << endl;
            return 1;

        }
    } else {

        cerr << "Fork failed..." << strerror(errno) << endl;
        return 1;

    }


    return 0;
}