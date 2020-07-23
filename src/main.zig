const std = @import("std");
const Allocator = std.mem.Allocator;

// Latest PE format documentation can be found at https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

// MS-DOS program pre-assembled
const msdos_program_sub = @embedFile("msdos_program_stub.bin");

/// ImageCharacteristics are flags used to indicate attributes of the object or image file.
pub const ImageCharacteristics = packed struct {
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

pub const MachineType = packed enum(u16) {
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
};

pub const Subsystem = packed enum(u16) {
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

const DOSMagic = [2]u8{ 'M', 'Z' };

pub const DOSHeader = packed struct {
    /// This is the "magic number" of an EXE file. The first byte of the file is 0x4d and the second is 0x5a.
    magic: [2]u8,
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
    characteristics: ImageCharacteristics,
};

pub const OptionalHeaderMagic = packed enum(u16) {
    /// 32-bit executable
    Nt32 = 0x10b,
    /// 64-bit executable
    Header64 = 0x20b,
    /// ROM image
    ROM = 0x107,
};

pub const DataDirectory = packed struct {
    virtual_address: u32,
    size: u32,
};

const ImageNumberOfDirectoryEntries = 16;

pub const DLLCharacteristics = struct {
    /// Image can handle a high entropy 64-bit virtual address space.
    pub const HighEntroyVA = 0x0020;
    /// DLL can be relocated at load time.
    pub const DynamicBase = 0x0040;
    /// Code Integrity checks are enforced.
    pub const ForceIntegrity = 0x0080;
    /// Image is NX compatible.
    pub const NXCompat = 0x0100;
    /// Isolation aware, but do not isolate the image.
    pub const NoIsolation = 0x0200;
    /// Does not use structured exception (SE) handling. No SE handler may be called in this image.
    pub const NoSEH = 0x0400;
    /// Do not bind the image.
    pub const NoBind = 0x0800;
    /// Image must execute in an AppContainer.
    pub const AppContainer = 0x1000;
    /// A WDM driver.
    pub const WDMDriver = 0x2000;
    /// Image supports Control Flow Guard.
    pub const GuardCF = 0x4000;
    /// Terminal Server aware.
    pub const TerminalServerAware = 0x8000;
};

pub const OptionalHeader32 = packed struct {
    magic: OptionalHeaderMagic,
    major_linker_version: u8,
    minor_linker_version: u8,
    sizeof_code: u32,
    sizeof_initialized_data: u32,
    sizeof_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32 = 0,
    sizeof_image: u32,
    sizeof_header: u32,
    checksum: u32,
    subsystem: Subsystem,
    dll_characteristics: u16,
    sizeof_stack_reverse: u32,
    sizeof_stack_commit: u32,
    sizeof_heap_reserve: u32,
    sizeof_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageNumberOfDirectoryEntries]DataDirectory,
};

pub const OptionalHeader64 = packed struct {
    magic: OptionalHeaderMagic,
    major_linker_version: u8,
    minor_linker_version: u8,
    sizeof_code: u32,
    sizeof_initialized_data: u32,
    sizeof_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32 = 0,
    sizeof_image: u32,
    sizeof_header: u32,
    checksum: u32,
    subsystem: Subsystem,
    dll_characteristics: u16,
    sizeof_stack_reverse: u64,
    sizeof_stack_commit: u64,
    sizeof_heap_reserve: u64,
    sizeof_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageNumberOfDirectoryEntries]DataDirectory,
};

const ImageSizeOfShortName = 8;

pub const SectionCharacteristics = struct {
    /// The section should not be padded to the next boundary.
    /// This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    pub const NoPad = 0x00000008;

    /// The section contains executable code.
    pub const ContentCode = 0x00000020;

    /// The section contains initialized data
    pub const InitializedData = 0x00000040;

    /// The section contains uninitialized data
    pub const UninitializedData = 0x00000080;

    /// Reserved for future use
    pub const LinkOther = 0x00000100;

    /// The section contains comments or other information.
    /// The .drectve section has this type. This is valid for object files only.
    pub const LinkInfo = 0x00000200;

    /// The section will not become part of the image. This is valid only for object files.
    pub const LinkRemove = 0x00000800;

    /// The section contains COMDAT data. This is valid only for object files.
    pub const LinkComdat = 0x00001000;

    /// The section contains data referenced through the global pointer (GP).
    pub const GpRel = 0x00008000;

    /// Reserved for future use.
    pub const MemPurgeable = 0x00020000;

    /// Reserved for future use.
    pub const MemLocked = 0x00040000;

    /// Reseved for future use.
    pub const MemPreload = 0x00080000;

    /// Align data on a 1-byte boundary. Valid only for object files.
    pub const Align1Bytes = 0x00100000;

    /// Align data on a 2-byte boundary. Valid only for object files.
    pub const Align2Bytes = 0x00200000;

    /// Align data on a 4-byte boundary. Valid only for object files.
    pub const Align4Bytes = 0x00300000;

    /// Align data on an 8-byte boundary. Valid only for object files.
    pub const Align8Bytes = 0x00400000;

    /// Align data on a 16-byte boundary. Valid only for object files.
    pub const Align16Bytes = 0x00500000;

    /// Align data on a 32-byte boundary. Valid only for object files.
    pub const Align32Bytes = 0x00600000;

    /// Align data on a 64-byte boundary. Valid only for object files.
    pub const Align64Bytes = 0x00700000;

    /// Align data on a 128-byte boundary. Valid only for object files.
    pub const Align128Bytes = 0x00800000;

    /// Align data on a 256-byte boundary. Valid only for object files.
    pub const Align256Bytes = 0x00900000;

    /// Align data on a 512-byte boundary. Valid only for object files.
    pub const Align512Bytes = 0x00A00000;

    /// Align data on a 1024-byte boundary. Valid only for object files.
    pub const Align1024Bytes = 0x00B00000;

    /// Align data on a 2048-byte boundary. Valid only for object files.
    pub const Align2048Bytes = 0x00C00000;

    /// Align data on a 4096-byte boundary. Valid only for object files.
    pub const Align4096Bytes = 0x00D00000;

    /// Align data on an 8192-byte boundary. Valid only for object files.
    pub const Align8192Bytes = 0x00E00000;

    /// The section contains extended relocations.
    pub const LinkNumRelocOverflow = 0x01000000;

    /// The section can be discarded as needed.
    pub const MemDiscardable = 0x02000000;

    /// The section cannot be cached.
    pub const MemNotCached = 0x04000000;

    /// The section is not pageable.
    pub const MemNotPaged = 0x08000000;

    /// The section can be shared in memory
    pub const MemShared = 0x10000000;

    /// The section can be executed as code.
    pub const MemExecute = 0x20000000;

    /// The section can be read.
    pub const MemRead = 0x40000000;

    /// The section can be written to.
    pub const MemWrite = 0x80000000;
};

pub const SectionHeader = packed struct {
    name: [ImageSizeOfShortName]u8,
    misc: packed union {
        physical_address: u32,
        virtual_size: u32,
    },
    virtual_address: u32,
    sizeof_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
};

pub const ImportDirectoryEntry = packed struct {
    lookup_relative_address: u32,
    timestamp: u32,
    forwarder_chain: u32,
    name_relative_address: u32,
    import_table_relative_address: u32,

    const Self = @This();

    pub fn isEndEntry(self: Self) bool {
        if (self.lookup_relative_address == 0 and self.timestamp == 0 and self.forwarder_chain == 0 and self.name_relative_address == 0 and self.import_table_relative_address == 0) {
            return true;
        }

        return false;
    }
};

pub const ImportLookupEntry32 = packed struct {
    value: union {
        ordinal: u16,
        name_relative_address: u31,
    },
    import_by_ordinal: bool,
};

pub const ImportLookupEntry64 = packed struct {
    value: union {
        ordinal: u16,
        name_relative_address: u62,
    },
    import_by_ordinal: bool,
};

pub const ImportHintEntry = packed struct {
    hint: u16,
    name: []const u8,
};

pub const ImportLookupEntry = union(enum) {
    pe32: ImportLookupEntry32,
    pe64: ImportLookupEntry64,
};

pub const ImageDirectoryEntryIndex = struct {
    pub const Export = 0;
    pub const Import = 1;
    pub const Resource = 2;
    pub const Exception = 3;
    pub const Security = 4;
    pub const BaseReloc = 5;
    pub const Debug = 6;
    pub const Architecture = 7;
    pub const GlobalPtr = 8;
    pub const ThreadLocalPointer = 9;
    pub const LoadConfig = 10;
    pub const BoundImport = 11;
    pub const ImportAddressTable = 12;
    pub const DelayImport = 13;
    pub const ComDescriptor = 14;
};

comptime {
    std.debug.assert(@sizeOf(DOSHeader) == 64);
    std.debug.assert(@sizeOf(COFFHeader) == 20);
    std.debug.assert(@sizeOf(OptionalHeader32) == 224);
    std.debug.assert(@sizeOf(OptionalHeader64) == 240);
    std.debug.assert(@sizeOf(SectionHeader) == 40);
}

const PEMagic = [4]u8{ 'P', 'E', 0, 0 };

fn peHeader(comptime OptionalType: type) type {
    return struct {
        coff: COFFHeader,
        optional: OptionalType,
    };
}

pub const PEHeader32 = peHeader(OptionalHeader32);
pub const PEHeader64 = peHeader(OptionalHeader64);

fn peFile(comptime PEHeaderType: type) type {
    return struct {
        dos_header: DOSHeader,
        pe_header: PEHeaderType,
        section_headers: []SectionHeader,

        const Self = @This();

        pub fn getSection(self: Self, name: []const u8) !SectionHeader {
            for (self.section_headers) |section| {
                const min_len = std.math.min(section.name.len, name.len);

                if (std.mem.order(u8, section.name[0..min_len], name) == .eq) {
                    return section;
                }
            }

            return error.SectionNotFound;
        }
    };
}

pub const PEFile32 = peFile(PEHeader32);
pub const PEFile64 = peFile(PEHeader64);

pub const PEFile = union(enum) {
    pe32: PEFile32,
    pe64: PEFile64,
};

fn readSections(allocator: *Allocator, in_stream: var, number_sections: usize) ![]SectionHeader {
    var section_headers = try allocator.alloc(SectionHeader, number_sections);
    errdefer allocator.free(section_headers);

    var index: usize = 0;
    while (index < number_sections) : (index += 1) {
        section_headers[index] = try in_stream.readStruct(SectionHeader);
    }

    return section_headers;
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_allocator = &arena.allocator;

    const args = try std.process.argsAlloc(arena_allocator);
    defer std.process.argsFree(arena_allocator, args);

    if (args.len < 1) {
        std.debug.warn("No input file provided.\n", .{});
        return;
    }

    const cwd = std.fs.cwd();

    const full_path = try std.fs.path.resolve(arena_allocator, &[_][]u8{args[1]});

    var file = try cwd.openFile(full_path, .{});

    var in_stream = file.inStream();
    var seek_stream = file.seekableStream();

    const dos_header = try in_stream.readStruct(DOSHeader);

    if (!std.mem.eql(u8, dos_header.magic[0..], DOSMagic[0..])) {
        std.debug.warn("Not a valid DOS program!\n", .{});
        return;
    }

    try seek_stream.seekTo(dos_header.pe_offset);

    var pe_magic: [4]u8 = undefined;
    _ = try in_stream.read(pe_magic[0..]);

    const coff_header = try in_stream.readStruct(COFFHeader);

    if (!std.mem.eql(u8, pe_magic[0..], PEMagic[0..])) {
        std.debug.warn("Not a valid PE image file\n", .{});
        return;
    }

    const optional_header_size = coff_header.sizeof_optional_header;

    std.debug.warn("DOS:\n{}\n", .{dos_header});
    std.debug.warn("COFF:\n{}\n", .{coff_header});
    std.debug.warn("Machine Type: {}\n", .{std.meta.tagName(coff_header.machine_type)});

    if (optional_header_size == @sizeOf(OptionalHeader32)) {
        std.debug.warn("PE/COFF x86 executable\n", .{});
        var pe_file: PEFile32 = undefined;

        pe_file.dos_header = dos_header;

        pe_file.pe_header.coff = coff_header;
        pe_file.pe_header.optional = try in_stream.readStruct(OptionalHeader32);

        std.debug.warn("\nOptional:\n\n{}\n", .{pe_file.pe_header.optional});

        std.debug.warn("\nRVA:\n\n", .{});

        for (pe_file.pe_header.optional.data_directory) |rva| {
            std.debug.warn("{}\n", .{rva});
        }

        pe_file.section_headers = try readSections(arena_allocator, in_stream, pe_file.pe_header.coff.number_of_sections);

        std.debug.warn("\nSections:\n\n", .{});

        for (pe_file.section_headers) |section| {
            std.debug.warn("{}\n", .{section});
        }
    } else if (optional_header_size == @sizeOf(OptionalHeader64)) {
        std.debug.warn("PE/COFF x86-64 executable\n", .{});

        var pe_file: PEFile64 = undefined;

        pe_file.dos_header = dos_header;

        pe_file.pe_header.coff = coff_header;
        pe_file.pe_header.optional = try in_stream.readStruct(OptionalHeader64);

        std.debug.warn("\nOptional:\n\n{}\n", .{pe_file.pe_header.optional});

        std.debug.warn("\nRVA:\n\n", .{});

        for (pe_file.pe_header.optional.data_directory) |rva| {
            std.debug.warn("{}\n", .{rva});
        }

        pe_file.section_headers = try readSections(arena_allocator, in_stream, pe_file.pe_header.coff.number_of_sections);

        std.debug.warn("\nSections:\n\n", .{});

        for (pe_file.section_headers) |section| {
            std.debug.warn("{}\n", .{section});
        }

        const import_section = try pe_file.getSection(".idata");

        try seek_stream.seekTo(import_section.pointer_to_raw_data);

        var image_directory_entry: ImportDirectoryEntry = try in_stream.readStruct(ImportDirectoryEntry);

        std.debug.warn("ImportDirectory Entries:\n\n", .{});

        while (!image_directory_entry.isEndEntry()) {
            std.debug.warn("{}\n", .{image_directory_entry});
            image_directory_entry = try in_stream.readStruct(ImportDirectoryEntry);
        }
    }
}
