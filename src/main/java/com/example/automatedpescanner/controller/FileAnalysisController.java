package com.example.automatedpescanner.controller;

import com.example.automatedpescanner.utils.PeInfo;
import com.example.automatedpescanner.utils.IFileParser;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/analyze")
@Tag(name = "Malware Analysis Engine", description = "Endpoints for parsing and analyzing Windows PE binaries")
public class FileAnalysisController {

    private final IFileParser fileParser;

    public FileAnalysisController( IFileParser fileParser )
    {
        this.fileParser = fileParser;
    }



    @PostMapping("/upload")
    @Operation(summary = "Upload and Analyze a PE file",
               description = "Parses the headers, calculates section entropy, extracts imported DLLs, and runs heuristics on a Windows executable."
    )
    public ResponseEntity<PeInfo> handleFileUpload(@RequestParam("file") MultipartFile file) throws Exception {

        if (file.isEmpty()) {
            throw new IllegalArgumentException("Please upload a file");
        }

        byte[] fileBytes = file.getBytes();


        if (!fileParser.isSupported(fileBytes)) {
            throw new IllegalArgumentException("Unsupported file format. Please upload a valid Windows PE file.");
        }

        PeInfo report = fileParser.analyze(fileBytes);

        return ResponseEntity.ok(report);
    }

}
