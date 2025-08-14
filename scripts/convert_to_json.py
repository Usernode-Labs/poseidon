#!/usr/bin/env python3
"""
Convert Poseidon parameter text files to structured JSON format
Parses SageMath output and extracts MDS matrix, round constants, and metadata
"""

import json
import re
import os
import sys
from typing import Dict, List, Any


def parse_poseidon_file(filepath: str) -> Dict[str, Any]:
    """Parse a Poseidon parameter file and extract structured data."""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Extract metadata from first line
    params_match = re.search(r'Params: n=(\d+), t=(\d+), alpha=(\d+), M=(\d+), R_F=(\d+), R_P=(\d+)', content)
    if not params_match:
        raise ValueError(f"Could not parse parameters from {filepath}")
    
    n, t, alpha, M, R_F, R_P = map(int, params_match.groups())
    
    # Extract modulus
    modulus_match = re.search(r'Modulus = (\d+)', content)
    if not modulus_match:
        raise ValueError(f"Could not parse modulus from {filepath}")
    
    modulus_decimal = int(modulus_match.group(1))
    
    # Extract hex modulus from "Prime number" line
    prime_match = re.search(r'Prime number: (0x[0-9a-fA-F]+)', content)
    modulus_hex = prime_match.group(1) if prime_match else hex(modulus_decimal)
    
    # Extract number of S-boxes and round constants
    sbox_match = re.search(r'Number of S-boxes: (\d+)', content)
    round_const_match = re.search(r'Number of round constants: (\d+)', content)
    
    num_sboxes = int(sbox_match.group(1)) if sbox_match else None
    num_round_constants = int(round_const_match.group(1)) if round_const_match else None
    
    # Extract round constants
    round_constants = []
    constants_match = re.search(r'Round constants for GF\(p\):\s*\[(.*?)\]', content, re.DOTALL)
    if constants_match:
        constants_str = constants_match.group(1)
        # Extract hex values
        hex_values = re.findall(r"'(0x[0-9a-fA-F]+)'", constants_str)
        round_constants = hex_values
    
    # Extract MDS matrix
    mds_matrix = []
    matrix_match = re.search(r'MDS matrix:\s*\[(.*?)\](?:\s|$)', content, re.DOTALL)
    if matrix_match:
        matrix_str = matrix_match.group(1)
        # Extract rows - each row is a list of hex values
        row_matches = re.findall(r'\[(.*?)\]', matrix_str)
        for row_str in row_matches:
            hex_values = re.findall(r"'(0x[0-9a-fA-F]+)'", row_str)
            if hex_values:  # Only add non-empty rows
                mds_matrix.append(hex_values)
    
    # Extract security algorithm results
    security_results = {}
    for i in range(1, 4):
        result_match = re.search(rf'Result Algorithm {i}:\s*\[([^\]]+)\]', content)
        if result_match:
            result_str = result_match.group(1)
            # Parse the result - could be True/False, numbers, or None
            if 'True' in result_str:
                security_results[f"algorithm_{i}"] = True
            elif 'False' in result_str:
                security_results[f"algorithm_{i}"] = False
            else:
                security_results[f"algorithm_{i}"] = result_str.strip()
    
    return {
        "metadata": {
            "field_size_bits": n,
            "state_size": t,
            "alpha": alpha,
            "security_level": M,
            "full_rounds": R_F,
            "partial_rounds": R_P,
            "total_rounds": R_F + R_P,
            "num_sboxes": num_sboxes,
            "num_round_constants": num_round_constants,
            "modulus": {
                "decimal": str(modulus_decimal),
                "hex": modulus_hex
            }
        },
        "round_constants": round_constants,
        "mds_matrix": mds_matrix,
        "security_validation": security_results
    }


def determine_curve_info(filename: str) -> Dict[str, str]:
    """Determine curve information from filename."""
    curve_mapping = {
        "bn254": {
            "curve_name": "BN254",
            "description": "Barreto-Naehrig curve, most widely used in zkSNARK applications",
            "field_type": "base_field",
            "applications": ["Ethereum", "Tornado Cash", "zkSNARKs"]
        },
        "bls12_381": {
            "curve_name": "BLS12-381", 
            "description": "Barreto-Lynn-Scott curve, Ethereum 2.0 standard",
            "field_type": "base_field",
            "applications": ["Ethereum 2.0", "Zcash Sapling", "BLS signatures"]
        },
        "bls12_377": {
            "curve_name": "BLS12-377",
            "description": "Barreto-Lynn-Scott curve, recursive proof friendly", 
            "field_type": "base_field",
            "applications": ["Celo", "recursive proofs with BW6-761"]
        },
        "pallas": {
            "curve_name": "Pallas",
            "description": "Pasta curve forming cycle with Vesta",
            "field_type": "base_field", 
            "applications": ["Mina Protocol", "recursive SNARKs"]
        },
        "vesta": {
            "curve_name": "Vesta", 
            "description": "Pasta curve forming cycle with Pallas",
            "field_type": "base_field",
            "applications": ["Mina Protocol", "recursive SNARKs"] 
        }
    }
    
    for key, info in curve_mapping.items():
        if key in filename.lower():
            return info
    
    return {
        "curve_name": "Unknown",
        "description": "Unknown curve",
        "field_type": "unknown",
        "applications": []
    }


def main():
    """Convert all Poseidon parameter files to JSON."""
    
    # Find all poseidon parameter files
    param_files = []
    for file in os.listdir('.'):
        if file.startswith('poseidon_params_') and file.endswith('.txt'):
            param_files.append(file)
    
    if not param_files:
        print("No Poseidon parameter files found!")
        return
    
    print(f"Found {len(param_files)} parameter files to convert...")
    
    for filepath in param_files:
        try:
            print(f"Converting {filepath}...")
            
            # Parse the file
            data = parse_poseidon_file(filepath)
            
            # Add curve information
            curve_info = determine_curve_info(filepath)
            data["curve_info"] = curve_info
            
            # Generate output filename
            json_filename = filepath.replace('.txt', '.json')
            
            # Write JSON file
            with open(json_filename, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Created {json_filename}")
            
        except Exception as e:
            print(f"❌ Error converting {filepath}: {e}")
    
    print(f"\n🎉 Conversion complete! Generated {len(param_files)} JSON files.")


if __name__ == "__main__":
    main()