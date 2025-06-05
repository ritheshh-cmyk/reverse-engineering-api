# Reverse Engineering API

A powerful API for reverse engineering and binary analysis, built with Python and Docker.

## Features

- Binary Analysis
- Static Analysis
- Dynamic Analysis
- Network Analysis
- Android Analysis
- Ghidra Integration
- YARA Rules Support
- UPX Unpacking
- TrID File Identification

## Tools Included

- Ghidra
- YARA
- UPX
- TrID
- Radare2
- Capstone
- Unicorn
- Keystone
- Angr
- And many more...

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/reverse-engineering-api.git
cd reverse-engineering-api
```

2. Download Ghidra:
- Visit [Ghidra Releases](https://github.com/NationalSecurityAgency/ghidra/releases)
- Download `ghidra_11.3.2_PUBLIC_20250415.zip`
- Place it in the project root directory

3. Build and run with Docker:
```bash
docker-compose up --build
```

## API Endpoints

- `POST /api/analyze` - Upload and analyze a binary
- `GET /api/results/{id}` - Get analysis results
- `POST /api/yara` - Add YARA rules
- `GET /api/tools` - List available tools

## Development

### Prerequisites

- Docker
- Python 3.10+
- Git

### Local Development

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

2. Install dependencies:
```bash
pip install -r backend/requirements.txt
```

3. Run the development server:
```bash
python -m backend.app
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [YARA](https://github.com/VirusTotal/yara)
- [Radare2](https://github.com/radareorg/radare2)
- And all other open-source tools used in this project 