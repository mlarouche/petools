const std = @import("std");

// Latest PE format documentation can be found at https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

// MS-DOS program pre-assembled
const msdos_program_sub = @embedFile("msdos_program_stub.bin");

/// Characterics are flags used to indicate attributes of the object or image file.
pub const Characterics = packed struct {
    /// Image only, used to indicate if the image contains base relocations
    reloc_stripped: bool,
    /// Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    executuable_image: bool = true,
    /// COFF line numbers have been removed. This flag is deprecated and should be zero.
    line_number_stripped: bool = false,
    /// COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    local_symbols_stripped: bool = false,
    /// Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    aggresive_workingset_trim: bool = false,
    /// Application can handle > 2-GB addresses.
    large_address_aware: bool,
    /// his flag is reserved for future use.
    dummy: bool = false,
    /// Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    bytes_reversed_lo: bool = false,
    /// Machine is based on a 32-bit-word architecture.
    is_32bit_machine: bool,
    /// Debugging information is removed from the image file.
    debug_stripped: bool,
    /// If the image is on removable media, fully load it and copy it to the swap file.
    removable_run_from_swap: bool,
    /// If the image is on network media, fully load it and copy it to the swap file.
    net_run_from_swap: bool,
    /// The image file is a system file, not a user program.
    is_system: bool,
    /// The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
    is_dll: bool,
    /// The file should be run only on a uniprocessor machine.
    up_processor_only: bool,
    /// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    bytes_reversed_hi: bool = false,
};

pub const MachineType = enum(u16) {
    Unknown = 0x0,
    AM33 = 0x1d3,
    AMD64 = 0x8664,
    ARM = 0x1c0,
    ARM64 = 0xaa64,
    Thumb2 = 0x1c4,
    EFIByteCode = 0xebc,
    i386 = 0x14c,
    IA64 = 0x200,
    M32R = 0x9041,
    MIPS16 = 0x266,
    MIPSFPU = 0x366,
    MIPSFPUS16 = 0x466,
    PowerPC = 0x1f0,
    PowerPcFP = 0x1f1,
    MIPS_R4000 = 0x166,
    RISCV32 = 0x5032,
    RISCV64 = 0x5064,
    RISCV128 = 0x5128,
    SH3 = 0x1a2,
    SH3DSP = 0x1a3,
    SH4 = 0x1a6,
    SH5 = 0x1a8,
    Thumb = 0x1c2,
    WCEMIPSV2 = 0x169,
    _,
};

pub const Subsystem = packed enum {
    /// An unknown subsystem
    Unknown = 0,
    /// Device drivers and native Windows processes
    Native = 1,
    /// The Windows graphical user interface (GUI) subsystem
    WindowsGUI = 2,
    /// The Windows character subsystem
    WindowsCUI = 3,
    /// The OS/2 character subsystem
    OS2CUI = 5,
    /// The Posix character subsystem
    PosixCUI = 7,
    /// Native Win9x driver
    NativeWindowsx = 8,
    /// Windows CE
    WindowsCEGUI = 9,
    /// EFI application
    EFIApplication = 10,
    /// An EFI driver with boot services.
    EFIBootServiceDriver = 11,
    /// An EFI driver with run-time services
    EFIRuntimeDriver = 12,
    /// EFI ROM Image
    EFIRom = 13,
    /// Xbox
    Xbox = 14,
    /// Windows boot application.
    WindowsBootApplication = 16,
};

const DOSSignature = [2]u8{ 'M', 'Z' };

pub const DOSHeader = packed struct {
    /// This is the "magic number" of an EXE file. The first byte of the file is 0x4d and the second is 0x5a.
    signature: [2]u8,
    /// The number of bytes in the last block of the program that are actually used. If this value is zero, that means the entire last block is used.
    bytes_last_block: u16,
    /// Number of blocks in the file that are part of the EXE file. If [02-03] is non-zero, only that much of the last block is used.
    blocks_in_file: u16,
    /// Number of relocation entries stored after the header. May be zero.
    num_relocs: u16,
    /// Number of paragraphs in the header. The program's data begins just after the header, and this field can be used to calculate the appropriate file offset.
    header_paragraphs: u16,
    /// Number of paragraphs of additional memory that the program will need. This is the equivalent of the BSS size in a Unix program.
    min_extra_paragraphs: u16,
    /// Maximum number of paragraphs of additional memory
    max_extra_paragraphs: u16,
    /// Relative value of the stack segment.
    stack_segment: u16,
    /// Initial value of the SP register.
    stack_pointer_value: u16,
    /// Word checksum.
    checksum: u16,
    /// Initial value of the IP register.
    instruction_pointer_value: u16,
    /// Initial value of the CS register.
    code_segment: u16,
    /// Offset of the first relocation item in the file.
    reloc_table_offsets: u16,
    /// Overlay number. Normally zero, meaning that it's the main program.
    overlay_numbers: u16,
    reseverd1: [4]u16,
    oem_id: u16,
    oem_info: u16,
    reversed2: [10]u16,
    /// Aboslute offset to the PE header
    pe_offset: u32,
};

pub const COFFHeader = packed struct {
    /// The number that identifies the type of target machine.
    machine_type: MachineType,
    /// The number of sections. This indicates the size of the section table, which immediately follows the headers.
    number_of_sections: u16,
    /// The low 32 bits of the number of seconds since 00:00 January 1, 1970 that indicates when the file was created.
    timestap: u32,
    /// The file offset of the COFF symbol table, or zero if no COFF symbol table is present
    /// This value should be zero for an image because COFF debugging information is deprecated.
    pointer_symbol_table: u32,
    /// The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    number_of_symbols: u32,
    /// The size of the optional header, which is required for executable files but not for object files.
    /// his value should be zero for an object file.
    sizeof_optional_header: u16,
    /// The flags that indicate the attributes of the file
    characteristics: Characterics,
};

const PESignature = [4]u8{ 'P', 'E', 0, 0 };

pub const PEHeader = packed struct {
    signature: [4]u8,
    coff: COFFHeader,
};

pub fn main() anyerror!void {
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len < 1) {
        std.debug.warn("No input file provided.\n", .{});
        return;
    }

    const cwd = std.fs.cwd();

    const full_path = try std.fs.path.resolve(std.heap.page_allocator, &[_][]u8{args[1]});

    std.debug.warn("Input: {}\n", .{full_path});

    var file = try cwd.openFile(full_path, .{});

    var in_stream = file.inStream();
    var seek_stream = file.seekableStream();

    const dos_header = try in_stream.readStruct(DOSHeader);

    if (!std.mem.eql(u8, dos_header.signature[0..], DOSSignature[0..])) {
        std.debug.warn("Not a valid DOS program!\n", .{});
        return;
    }

    try seek_stream.seekTo(dos_header.pe_offset);

    const pe_header = try in_stream.readStruct(PEHeader);

    if (!std.mem.eql(u8, pe_header.signature[0..], PESignature[0..])) {
        std.debug.warn("Not a valid PE image file\n", .{});
        return;
    }

    std.debug.warn("DOS:\n{}\n", .{dos_header});
    std.debug.warn("PE:\n{}\n", .{pe_header});
    std.debug.warn("Machine Type: {}\n", .{std.meta.tagName(pe_header.coff.machine_type)});
}
