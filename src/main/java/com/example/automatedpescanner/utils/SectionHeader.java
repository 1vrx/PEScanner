package com.example.automatedpescanner.utils;

public record SectionHeader(
        String name,
        int virtualSize,
        int virtualAddress, // RVA
        int rawSize,
        int rawAddress,     // PointerToRawData
        double entropy
) {}