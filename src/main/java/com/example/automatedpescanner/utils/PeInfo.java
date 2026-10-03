package com.example.automatedpescanner.utils;

import org.springframework.context.annotation.Import;

import java.util.List;

public record PeInfo(
        String md5,
        String sha256,
        String architecture,
        int sectionCount,
        int entryPointAddr,
        long fileSize,
        boolean isValid,
        List<SectionHeader> sections,
        List<ImportedDll> imports,
        List<String> warnings
) {}
