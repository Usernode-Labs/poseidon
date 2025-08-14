# Poseidon Parameter Generation Scripts

This folder contains scripts for generating and managing Poseidon hash function parameters.

## Scripts

- **`generate_parameters.py`** - Main parameter generation script that creates Rust parameter files from SageMath reference implementation
- **`generate_params_poseidon.sage`** - SageMath reference implementation for parameter generation
- **`convert_params.py`** - Utility for converting parameter formats
- **`convert_to_json.py`** - Utility for converting parameters to JSON format
- **`Dockerfile`** - Docker configuration for SageMath environment
- **`docker-compose.yml`** - Docker Compose configuration for parameter generation

## Usage

To generate parameters, run from the project root:

```bash
python3 scripts/generate_parameters.py
```

This will:
1. Run the SageMath script in Docker to generate parameters
2. Convert them directly to Rust constant files
3. Place them in `src/parameters/`

## Prerequisites

- Docker (for SageMath execution)
- Python 3.x
- The SageMath reference script (`generate_params_poseidon.sage`)