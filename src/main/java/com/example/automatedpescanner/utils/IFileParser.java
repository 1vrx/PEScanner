package com.example.automatedpescanner.utils;

import org.springframework.stereotype.Service;

@Service
public interface IFileParser {
    public boolean isSupported(byte[] b);
    public long getSize();
    public String getName();
    public String[] getImports();
    public String[] getExports();
    public String[] getSections();
    public String[] getEntropy();
    public PeInfo analyze(byte[] b);
}
