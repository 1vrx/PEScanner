
# Automated PE Binary Analysis Engine

A RESTful malware analysis engine and dashboard built to parse Windows PE/COFF binaries, calculate section-level Shannon entropy, and extract Import Address Tables (IAT) for heuristic analysis. 

The backend is built with **Spring Boot 3** and **Java 21**, The frontend is a zero-configuration, single-page dashboard inspired by classic 2010 UI aesthetics, served directly from the Spring Boot static context.

## Features

*   **PE Header Parsing:** Extracts core architecture, file size, and Entry Point (RVA) information.
*   **Heuristic Detection (IAT):** Parses the Import Address Table and flags suspicious API calls (e.g., `VirtualAlloc`, `CreateRemoteThread`) commonly associated with process injection or evasion.
*   **Memory Section Entropy:** Calculates Shannon entropy for individual PE sections to detect packed, compressed, or encrypted payloads (flagging sections with entropy > 7.2).
*   **Defensive API Architecture:** Utilizes Spring `@RestControllerAdvice` for global exception handling, gracefully catching malformed binaries or memory out-of-bounds errors and returning standardized JSON error schemas.
*   **Interactive Dashboard:** A compact, classic dark theme UI featuring drag-and-drop uploads, live status indicators, and dynamic Microsoft Learn documentation links for all extracted APIs.

## Tech Stack

*   **Core:** Java 21, Spring Boot 3.3.4
*   **API Documentation:** SpringDoc OpenAPI (Swagger 2.6.0)
*   **Build Tool:** Gradle (with Foojay toolchain resolver)
*   **Frontend:** Vanilla HTML5, CSS3, JavaScript (Flexbox, Fetch API)

### Prerequisites
*   **Java 21** installed on your machine.
*   No need to install Gradle manually; the project uses the Gradle Wrapper.

### Installation & Execution
1. Clone the repository:
   ```bash
   git clone [https://github.com/1vrx/AutomatedPEScanner.git](https://github.com/1vrx/AutomatedPEScanner.git)
   cd AutomatedPEScanner
   ```

   ![PE Scanner Dashboard]([https://img.lightshot.app/bVQeFWpJR92q0sDXjR3L0g.png])
