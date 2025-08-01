# APT Search Engine

## Overview
The **APT Search Engine** is a Python-based tool designed for cybersecurity researchers and threat intelligence analysts to perform comprehensive searches for Advanced Persistent Threat (APT) groups across multiple reputable threat intelligence databases. It aggregates and formats data from various sources, providing detailed insights into APT group activities, techniques, and associated resources.

The tool is created by **Muhap Yahia** and supports searching through databases like ETDA, MITRE ATT&CK, Google Cloud, NetEnrich, SOCRadar, Pulsedive, QiAnXin, Malpedia, and APTnotes. It also generates MITRE ATT&CK Navigator JSON files and detailed reports for further analysis.

## Features
- **Multi-Source Search**: Queries multiple threat intelligence databases simultaneously, including:
  - ETDA APT database
  - MITRE ATT&CK framework
  - Google Cloud APT Groups
  - NetEnrich Knowledge Base
  - SOCRadar Threat Intelligence
  - Pulsedive Threat Intelligence
  - QiAnXin Threat Intelligence
  - Malpedia Database
  - APTnotes Research Reports
- **Detailed Output**: Provides formatted, color-coded results with information such as:
  - APT group names, countries, motivations, and first seen dates
  - Observed sectors, countries, and tools used
  - Known operations and additional references
  - MITRE ATT&CK techniques and associated groups
- **File Generation**:
  - Saves MITRE ATT&CK Navigator JSON files for visualization
  - Generates detailed text reports of MITRE techniques
- **Flexible Search**:
  - Supports various APT name formats and aliases
  - Handles partial matches and case-insensitive searches
- **User-Friendly Interface**:
  - Displays a stylized ASCII banner
  - Uses color-coded output for better readability
  - Provides a summary of search results and total resources found
- **Error Handling**: Robust exception handling to ensure reliable operation even if some sources are unavailable
- **Customizable**: Easily extensible to add new data sources or modify existing ones

## Installation
1. **Clone the Repository** (if applicable):
   ```bash
   git clone https://github.com/mohabye/APT-Search-Engine/
   cd apt-search-engine
   ```

2. **Install Python**:
   Ensure Python 3.6 or higher is installed on your system.

3. **Install Dependencies**:
   The tool requires the following Python libraries:
   - `requests`
   - `beautifulsoup4`
   - `urllib3`

   Install them using pip:
   ```bash
   pip install requests beautifulsoup4 urllib3
   ```

4. **Run the Tool**:
   Execute the script directly:
   ```bash
   python apt_search_engine.py
   ```

## Usage
1. Launch the tool by running:
   ```bash
   python apt_search_engine.py
   ```

2. Enter the name of the APT group you want to search for when prompted (e.g., `Lazarus Group`, `APT28`).

3. The tool will:
   - Query all configured databases
   - Display results in a color-coded, formatted output
   - Save MITRE ATT&CK Navigator JSON and text report files (if applicable)
   - Provide a summary of findings, including total resources found and saved files

4. Example Output:
   ```
   Enter APT group name to search: Lazarus Group

   Comprehensive APT Search for: Lazarus Group
   ==================================================
   Searching ETDA database...
   Found ETDA result
   Searching MITRE ATT&CK database...
   Found MITRE ATT&CK data with 45 techniques
   Saved MITRE files to device: Lazarus_Group_MITRE_Navigator.json, Lazarus_Group_MITRE_Techniques_Report.txt
   ...

   SEARCH RESULTS
   ========================================================================
   ETDA APT GROUP INFORMATION
   ========================================================================
   Basic Information:
   Names: Lazarus Group, Hidden Cobra
   Country: North Korea
   Motivation: Espionage, Financial Gain
   First seen: 2009
   ...

   COMPREHENSIVE SEARCH SUMMARY
   ==============================================================================================================
   ETDA Database: Found
   MITRE ATT&CK: Found
   Google Cloud APT: 1 profiles found
   ...
   Total Resources Found: 128
   ```

<img width="1635" height="916" alt="image" src="https://github.com/user-attachments/assets/436ac525-dea0-43ff-97ab-3562ca83e7cf" />

<img width="1661" height="971" alt="image" src="https://github.com/user-attachments/assets/cdc0bbe1-2237-448b-801d-c4bbd601edb6" />



5. **Tips for Effective Searches**:
   - Use alternative names or aliases (e.g., `Hidden Cobra` for `Lazarus Group`)
   - Try numbers instead of text (e.g., `APT28` instead of `Fancy Bear`)
   - Use partial names (e.g., `Lazarus` instead of `Lazarus Group`)

## Output Files
- **MITRE ATT&CK Navigator JSON** (`<APT_NAME>_MITRE_Navigator.json`):
  - Contains techniques used by the APT group in a format compatible with MITRE ATT&CK Navigator
  - Useful for visualizing attack patterns
- **MITRE Techniques Report** (`<APT_NAME>_MITRE_Techniques_Report.txt`):
  - Detailed text report listing group information and techniques
  - Includes group IDs, names, descriptions, and technique usage

