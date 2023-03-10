#include <format>
#include <fstream>
#include <iostream>
#include <unordered_set>
#include <vector>

#include "linux-pe/includes/nt/image.hpp"

template <typename ... Ts>
void print(const std::string_view msg, Ts&&... args) {
	std::cout << "[vmp-analyzer] " << std::vformat(msg, std::make_format_args(std::forward<Ts>(args)...));
}

using image_t = win::image_t<win::default_architecture>;
using nt_headers_t = win::nt_headers_t<win::default_architecture>;

struct vm_entry_info_t {
	std::string_view m_section;
	uintptr_t m_address;
};

static constexpr bool X64 = win::default_architecture;
static constexpr uint8_t CALL_REL = 0xE8;
static constexpr uint8_t JMP_REL32 = 0xE9;
static constexpr uint8_t PUSH_IMM = 0x68;
static constexpr size_t VM_ENTRY_SIZE = 10;
static constexpr size_t JMP_CALL_REL32_SIZE = 5;

static std::vector<vm_entry_info_t> entries;
static std::unordered_set<uintptr_t> visited;

std::vector<uint8_t> read_binary_file(const char* file) {
	std::ifstream file_in(file, std::ios::binary);

	if (!file_in.good())
		return {};

	return { std::istreambuf_iterator<char>(file_in), {} };
}

bool is_jmp_or_push_imm(uint8_t* p) {
	return *p == PUSH_IMM || *p == JMP_REL32;
}

bool is_vm_entry_call(uint8_t* p) {
	return *p == PUSH_IMM && p[5] == CALL_REL;
}

bool is_push_reg_or_flag(uint8_t* p) {
	// 0x9C = pushf, 0x60 = pusha, 0x50 -> 0x57 = push r + reg number, 0x41 = Instruction Prefix (x64 only).
	return *p == 0x9C || *p == 0x60 || *p >= 0x50 && *p <= 0x57 || *p == 0x41 && p[1] >= 0x50 && p[1] <= 0x57;
}

std::string get_formatted_datetime() {
	tm tm_buf;
	time_t tm;

	time(&tm);
	localtime_s(&tm_buf, &tm);

	std::string buf(260, '\0');
	strftime(&buf[0], buf.size(), "%F.%H_%M_%S", &tm_buf);
	return buf.substr(0, buf.find('\0'));
}

int main(int argc, char** argv) {

	const char* usage = "Usage: vmp-analyzer.exe <input file> -xrefs or -entries";

	try {
		if (argc < 3)
			throw std::exception(usage);

		if (strcmp(argv[2], "-xrefs") != 0 && strcmp(argv[2], "-entries") != 0)
			throw std::exception(usage);

		const char* source = argv[1];

		auto raw_bin = read_binary_file(source);

		if (raw_bin.empty())
			throw std::exception("Binary couldn't be read\n");

		// Should we list xrefs?
		const bool list_xrefs = strcmp(argv[2], "-xrefs") == 0;

		const auto win_img = std::bit_cast<image_t*>(raw_bin.data());

		if (win_img->get_dos_headers()->e_magic != win::DOS_HDR_MAGIC)
			throw std::exception("Binary doesn't have a valid DOS signature.\n");

		const auto nt_headers = win_img->get_nt_headers();

		if (nt_headers->signature != win::NT_HDR_MAGIC)
			throw std::exception("Binary doesn't have a valid NT signature.\n");

		if (nt_headers->file_header.characteristics.machine_32 && X64)
			throw std::exception("Please use the 32-bit version of this tool to analyze 32-bit binaries.\n");

		if (!nt_headers->file_header.characteristics.machine_32 && !X64)
			throw std::exception("Please use the 64-bit version of this tool to analyze 64-bit binaries.\n");

		print("Sections: {}\n", nt_headers->file_header.num_sections);
		print("VMP Entry point : 0x{:X}\n", nt_headers->optional_header.image_base + nt_headers->optional_header.entry_point);

		const auto vmp_cs = win_img->rva_to_section(nt_headers->optional_header.entry_point);

		if (!vmp_cs)
			throw std::exception("Couldn't determine section from the entry point rva.\n");

		if (!vmp_cs->characteristics.mem_read && !vmp_cs->characteristics.mem_execute)
			throw std::exception("Weird, VMP entry point's section doesn't have RX privileges.\n");

		const std::string_view vmp_cs_name = vmp_cs->name.to_string();

		uint8_t* sec_start = raw_bin.data() + vmp_cs->ptr_raw_data;

		for (uint8_t* p = raw_bin.data() + vmp_cs->ptr_raw_data; p < raw_bin.data() + vmp_cs->ptr_raw_data + vmp_cs->size_raw_data - VM_ENTRY_SIZE; ++p) {
			if (!is_jmp_or_push_imm(p))
				continue;

			uint8_t* tmp = p;

			// If we are at a jmp, follow it.
			if (*tmp == JMP_REL32) {
				const auto jmp_rva = uint32_t(vmp_cs->virtual_address + tmp - sec_start + JMP_CALL_REL32_SIZE + *std::bit_cast<int32_t*>(&tmp[1]));

				// Make sure the section resolved from the rva matches the code section.
				if (win_img->rva_to_section(jmp_rva) != vmp_cs)
					continue;

				// Follow the call, at this point we should have an address for vmentry.
				tmp += JMP_CALL_REL32_SIZE + *std::bit_cast<int32_t*>(&tmp[1]);

				// Compensate for the 1 each iter adds.
				p += VM_ENTRY_SIZE - 1;
			}

			// Follow the relative call.
			const auto call_rva = uint32_t(vmp_cs->virtual_address + tmp - sec_start + VM_ENTRY_SIZE + *std::bit_cast<int32_t*>(&tmp[6]));
			uint8_t* call_dst = tmp + VM_ENTRY_SIZE + *std::bit_cast<int32_t*>(&tmp[6]);

			// Make sure it matches conditions for vm entry.
			if (win_img->rva_to_section(call_rva) != vmp_cs || !is_vm_entry_call(tmp) || !is_push_reg_or_flag(call_dst))
				continue;

			// Compensate for the 1 each iter adds.
			p += JMP_CALL_REL32_SIZE - 1;

			// Get xref or virtual address of the vm entry.
			const uintptr_t vm_entry_addr = list_xrefs
				? nt_headers->optional_header.image_base + vmp_cs->virtual_address + tmp - sec_start
				: nt_headers->optional_header.image_base + vmp_cs->virtual_address + call_dst - sec_start;

			// Make sure we haven't stored this entry.
			if (visited.find(vm_entry_addr) == visited.end()) {
				visited.insert(vm_entry_addr);
				entries.push_back({ .m_section = vmp_cs_name.data(), .m_address = vm_entry_addr });
			}
		}

		print("Scanned all {} (found {}).\n", list_xrefs ? "VM Entry xrefs" : "VM Entries", entries.size());

		const std::string_view dst_tmp = source;

		// Create a file with the following format: <file name>_<date>-.<time>
		const std::string dmp_file = std::format("{}_{}.txt", dst_tmp.substr(dst_tmp.find_last_of('\\') + 1), get_formatted_datetime());

		std::ofstream file_out(dmp_file);

		file_out << std::vformat(list_xrefs ? "VM Entry xrefs: {}\n" : "VM Entries: {}\n", std::make_format_args(entries.size()));

		// Sort by address low -> high
		std::ranges::sort(entries, [](auto a, auto b) {return a.m_address < b.m_address; });

		for (const auto& [sec, addr] : entries)
			file_out << std::vformat("{}:{:X}\n", std::make_format_args(sec, addr));

		print("Saved results to {}.\n", dmp_file);
	}
	catch (const std::exception& e) {
		print(e.what());
		std::exit(1);
	}
}
