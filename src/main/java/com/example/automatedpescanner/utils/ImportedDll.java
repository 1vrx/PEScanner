package com.example.automatedpescanner.utils;

import java.util.List;

public record ImportedDll(
        String dllName,
        List<String> functions
) {}
