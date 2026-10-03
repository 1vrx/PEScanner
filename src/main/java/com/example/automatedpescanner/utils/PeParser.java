package com.example.automatedpescanner.utils;

import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

@Service
public class PeParser implements IFileParser {

    @Override
    public boolean isSupported(byte[] b) {

        if (b == null || b.length < (0x40) ) {return false;}
        //Windows PE 'MZ' & 'PE' header
        if (b[0] != 0x4D || b[1] != 0x5A) {return false;}

        ByteBuffer bytes = ByteBuffer.wrap(b);
        bytes.order(ByteOrder.LITTLE_ENDIAN);
        int peOffset = bytes.getInt(0x3C);
        if (peOffset > b.length - 4) return false;

        int peSignature = bytes.getInt(peOffset);
        return peSignature == 0x00004550; // 0x00004550 == 'PE\0\0'

    }

    @Override
    public long getSize() {
        return 0;
    }

    @Override
    public String getName() {
        return "";
    }

    @Override
    public String[] getImports() {
        return new String[0];
    }

    @Override
    public String[] getExports() {
        return new String[0];
    }

    @Override
    public String[] getSections() {
        return new String[0];
    }

    @Override
    public String[] getEntropy() {
        return new String[0];
    }

    //https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    @Override
    public PeInfo analyze(byte[] b) {

        String md5 = calculateHash(b, "MD5");
        String sha256 = calculateHash(b, "SHA-256");

        if (!isSupported(b)) {
            return new PeInfo(md5, sha256, "UNKNOWN", 0, 0, b.length, false, new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
        }


        ByteBuffer bytes = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        int peOffset = bytes.getInt(0x3C);

        int coffHeaderOffset = peOffset + 4;

        short rawMachine = bytes.getShort(coffHeaderOffset);
        int machineType = rawMachine & 0xFFFF;
        String architecture = (machineType == 0x8664) ? "x64" :
                (machineType == 0x014c) ? "x86" : "Unknown";

        int entryPointAddr = bytes.getInt(peOffset + 0x28);

        short rawSectionCount = bytes.getShort(coffHeaderOffset + 2);
        int numberOfSections = rawSectionCount & 0xFFFF;

        short rawSizeOfOptionalHeader = bytes.getShort(coffHeaderOffset + 16);
        int sizeOfOptionalHeader = rawSizeOfOptionalHeader & 0xFFFF;

        int sectionTableOffset = coffHeaderOffset + 20 + sizeOfOptionalHeader;

        List<SectionHeader> sections = parseSections(bytes, sectionTableOffset, numberOfSections);
        List<ImportedDll> imports = parseImports(bytes, coffHeaderOffset + 20, architecture.equals("x64"), sections);
        List<String> warnings = runHeuristics(sections, imports);
        return new PeInfo(md5, sha256, architecture, numberOfSections, entryPointAddr, b.length, true, sections, imports, warnings);
    }


    private List<SectionHeader> parseSections(ByteBuffer bytes, int sectionTableOffset, int sectionCount) {
        List<SectionHeader> sections = new ArrayList<>();

        for (int i = 0; i < sectionCount; i++) {
            int currentOffset = sectionTableOffset + (i * 40);

            byte[] nameBytes = new byte[8];
            bytes.position(currentOffset);
            bytes.get(nameBytes);
            String name = new String(nameBytes).trim();

            int virtualSize = bytes.getInt(currentOffset + 8);
            int virtualAddress = bytes.getInt(currentOffset + 12);
            int rawSize = bytes.getInt(currentOffset + 16);
            int rawAddress = bytes.getInt(currentOffset + 20);

            double entropy = 0.0;

            if (rawSize > 0 && rawAddress > 0 && (rawAddress + rawSize) <= bytes.capacity()) {
                byte[] sectionData = new byte[rawSize];
                bytes.position(rawAddress);
                bytes.get(sectionData);

                entropy = calculateShannonEntropy(sectionData);
            }

            sections.add(new SectionHeader(name, virtualSize, virtualAddress, rawSize, rawAddress, entropy));
        }

        return sections;
    }

    private List<ImportedDll> parseImports(ByteBuffer bytes, int optionalHeaderOffset, boolean is64Bit, List<SectionHeader> sections) {
        List<ImportedDll> imports = new ArrayList<>();

        int dataDirectoryOffset = is64Bit ? optionalHeaderOffset + 112 : optionalHeaderOffset + 96;

        int importDirRva = bytes.getInt(dataDirectoryOffset + 8);
        if (importDirRva == 0) {
            return imports; //suspicious todo: add a flag for this on the frontend
        }

        int importDirOffset = rvaToOffset(importDirRva, sections);
        if (importDirOffset == 0) return imports;

        int currentDescriptorOffset = importDirOffset;

        while (true) {
            int originalFirstThunk = bytes.getInt(currentDescriptorOffset);
            int nameRva = bytes.getInt(currentDescriptorOffset + 12);
            int firstThunk = bytes.getInt(currentDescriptorOffset + 16);

            if (nameRva == 0 && firstThunk == 0) break;

            int nameOffset = rvaToOffset(nameRva, sections);
            String dllName = nameOffset > 0 ? readNullTerminatedString(bytes, nameOffset) : "Unknown.dll";

            List<String> functions = new ArrayList<>();

            int thunkRva = (originalFirstThunk != 0) ? originalFirstThunk : firstThunk;
            int currentThunkOffset = rvaToOffset(thunkRva, sections);

            if (currentThunkOffset > 0) {
                while (true) {
                    long thunkData;
                    if (is64Bit) {
                        thunkData = bytes.getLong(currentThunkOffset);
                        currentThunkOffset += 8;
                    } else {
                        thunkData = bytes.getInt(currentThunkOffset) & 0xFFFFFFFFL;
                        currentThunkOffset += 4;
                    }

                    if (thunkData == 0) break;

                    boolean isOrdinal = is64Bit ? (thunkData & 0x8000000000000000L) != 0 : (thunkData & 0x80000000L) != 0;

                    if (isOrdinal) {
                        long ordinal = thunkData & 0xFFFF;
                        functions.add("Ordinal_" + ordinal);
                    } else {
                        int importByNameRva = (int) (thunkData & 0x7FFFFFFF);
                        int importByNameOffset = rvaToOffset(importByNameRva, sections);

                        if (importByNameOffset > 0) {
                            String functionName = readNullTerminatedString(bytes, importByNameOffset + 2);
                            functions.add(functionName);
                        }
                    }
                }
            }

            imports.add(new ImportedDll(dllName, functions));
            currentDescriptorOffset += 20;
        }

        return imports;
    }

    private double calculateShannonEntropy(byte[] data) {
        if (data == null || data.length == 0) {
            return 0.0;
        }

        int[] frequencies = new int[256];
        for (byte b : data) {
            frequencies[b & 0xFF]++;
        }

        double entropy = 0.0;
        double dataLength = data.length;

        for (int count : frequencies) {
            if (count > 0) {
                double probability = count / dataLength;
                //H = -Sum(P * log2(P))
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }

        //round to make json cleaner
        return Math.round(entropy * 100.0) / 100.0;
    }

    private int rvaToOffset(int rva, List<SectionHeader> sections) {
        if (rva == 0) return 0;

        for (SectionHeader section : sections) {
            int vStart = section.virtualAddress();
            int vEnd = vStart + section.virtualSize();

            if (rva >= vStart && rva < vEnd) {
                return rva - vStart + section.rawAddress();
            }
        }
        return 0;
    }

    private String readNullTerminatedString(ByteBuffer bytes, int offset) {
        if (offset <= 0 || offset >= bytes.capacity()) return "";

        bytes.position(offset);
        StringBuilder sb = new StringBuilder();
        while (bytes.hasRemaining()) {
            byte b = bytes.get();
            if (b == 0) break; // null terminator
            sb.append((char) b);
        }
        return sb.toString();
    }

    private String calculateHash(byte[] fileBytes, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);

            byte[] hashBytes = digest.digest(fileBytes);

            return HexFormat.of().formatHex(hashBytes);

        } catch (Exception e) {
            return "Hash_Error";
        }
    }

    private List<String> runHeuristics(List<SectionHeader> sections, List<ImportedDll> imports) {
        List<String> warnings = new ArrayList<>();

        Set<String> suspiciousApis = Set.of(
                "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "SetWindowsHookEx", "LoadLibraryA", "GetProcAddress", "IsDebuggerPresent"
        );

        int suspiciousApiCount = 0;
        for (ImportedDll dll : imports) {
            for (String function : dll.functions()) {
                if (suspiciousApis.contains(function)) {
                    warnings.add("Suspicious API detected: " + function + " (Often used in Process Injection/Evasion)");
                    suspiciousApiCount++;
                }
            }
        }

        if (suspiciousApiCount > 3) {
            warnings.add("CRITICAL: Multiple process injection or evasion APIs detected. High probability of malicious intent.");
        }

        for (SectionHeader section : sections) {
            if (section.entropy() > 7.2) {
                warnings.add(String.format(
                        "High entropy (%.2f) detected in section '%s'. Binary is likely packed or encrypted (e.g., UPX, Themida).",
                        section.entropy(), section.name()
                ));
            }

            if (section.rawSize() == 0 && section.virtualSize() > 4096) {
                warnings.add(String.format(
                        "Suspicious section size in '%s': Allocates %d bytes in memory but has 0 bytes on disk. " +
                                "This is a classic indicator of a packed executable.",
                        section.name(), section.virtualSize()
                ));
            }
        }

        return warnings;
    }

}
