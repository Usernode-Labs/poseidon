#!/usr/bin/env python3
"""Convert JSON Poseidon parameters to Rust constants."""

import json
import sys
from pathlib import Path

def convert_to_rust_constants(json_file, curve_name, field_type):
    """Convert JSON parameters to Rust constant definitions."""
    
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    metadata = data['metadata']
    
    # Generate Rust code
    rust_code = f'''//! Poseidon parameters for {curve_name} curve.
//!
//! Generated from the official Poseidon reference implementation
//! with t={metadata['state_size']}, α={metadata['alpha']}, M={metadata['security_level']} security level.

use crate::ark_poseidon::ArkPoseidonConfig;
use lazy_static::lazy_static;

/// Number of full rounds
pub const FULL_ROUNDS: usize = {metadata['full_rounds']};

/// Number of partial rounds  
pub const PARTIAL_ROUNDS: usize = {metadata['partial_rounds']};

/// Round constants for {curve_name}
pub const ROUND_CONSTANTS: [&str; {metadata['num_round_constants']}] = [
'''
    
    # Add round constants
    for i, rc in enumerate(data['round_constants']):
        rust_code += f'    "{rc}",\n'
    
    rust_code += '];\n\n'
    
    # Add MDS matrix
    rust_code += f'/// MDS matrix for {curve_name}\n'
    rust_code += f'pub const MDS_MATRIX: [[&str; {metadata["state_size"]}]; {metadata["state_size"]}] = [\n'
    
    for row in data['mds_matrix']:
        rust_code += '    ['
        for j, elem in enumerate(row):
            rust_code += f'"{elem}"'
            if j < len(row) - 1:
                rust_code += ', '
        rust_code += '],\n'
    
    rust_code += '];\n\n'
    
    # Add lazy static for parameters
    rust_code += f'''lazy_static! {{
    /// Poseidon parameters for {curve_name} {field_type} field
    pub static ref {curve_name.upper()}_PARAMS: ArkPoseidonConfig<ark_{curve_name.lower()}::{field_type}> = {{
        use num_bigint::BigUint;
        
        // Parse round constants
        let mut ark = Vec::new();
        for hex_str in ROUND_CONSTANTS.iter() {{
            let cleaned = hex_str.trim_start_matches("0x");
            let big_int = BigUint::parse_bytes(cleaned.as_bytes(), 16).unwrap();
            ark.push(ark_{curve_name.lower()}::{field_type}::from(big_int));
        }}
        
        // Parse MDS matrix
        let mut mds = Vec::new();
        for row in MDS_MATRIX.iter() {{
            let mut mds_row = Vec::new();
            for hex_str in row.iter() {{
                let cleaned = hex_str.trim_start_matches("0x");
                let big_int = BigUint::parse_bytes(cleaned.as_bytes(), 16).unwrap();
                mds_row.push(ark_{curve_name.lower()}::{field_type}::from(big_int));
            }}
            mds.push(mds_row);
        }}
        
        crate::parameters::create_parameters(
            ark,
            mds,
            FULL_ROUNDS,
            PARTIAL_ROUNDS,
        )
    }};
}}
'''
    
    return rust_code

# Process each curve
curves = [
    ('pallas', 'Fq'),
    ('vesta', 'Fq'),
    ('bn254', 'Fq'),
    ('bls12_381', 'Fq'),
    ('bls12_377', 'Fq'),
]

for curve, field in curves:
    json_file = f'poseidon_params_{curve}_t3_alpha5_M128.json'
    if Path(json_file).exists():
        rust_code = convert_to_rust_constants(json_file, curve, field)
        output_file = f'src/parameters/{curve}.rs'
        with open(output_file, 'w') as f:
            f.write(rust_code)
        print(f"Generated {output_file}")
    else:
        print(f"Warning: {json_file} not found")
