#!/usr/bin/env python3
"""
Unified Poseidon parameter generation script.
Generates Rust parameter files directly from the SageMath reference implementation.

Usage:
    python3 generate_parameters.py

This will:
1. Run the SageMath script in Docker to generate parameters
2. Convert them directly to Rust constant files
3. Place them in src/parameters/
"""

import subprocess
import json
import os
import sys
from pathlib import Path
import tempfile
import re

# Curve configurations
CURVES = [
    {
        'name': 'pallas',
        'prime': '0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001',
        'field_type': 'Fq',
        'description': 'Pallas curve (used in Mina Protocol)'
    },
    {
        'name': 'vesta',
        'prime': '0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001',
        'field_type': 'Fq',
        'description': 'Vesta curve (forms cycle with Pallas)'
    },
    {
        'name': 'bn254',
        'prime': '0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47',
        'field_type': 'Fq',
        'description': 'BN254 curve (Ethereum, zkSNARKs)'
    },
    {
        'name': 'bls12_381',
        'prime': '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab',
        'field_type': 'Fq',
        'description': 'BLS12-381 curve (Ethereum 2.0, Zcash)'
    },
    {
        'name': 'bls12_377',
        'prime': '0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001',
        'field_type': 'Fq',
        'description': 'BLS12-377 curve (Celo, recursive proofs)'
    },
]

# Standard parameters for all curves
T = 3  # State size
ALPHA = 5  # S-box exponent
M = 128  # Security level in bits


def run_sage_in_docker(prime, output_file):
    """Run the SageMath script in Docker to generate parameters."""
    
    # Create a temporary script that includes the prime
    sage_script = f"""
# Set the prime for parameter generation
prime = {prime}
p = prime

# Standard parameters
t = {T}
alpha = {ALPHA}
M = {M}

# Run the parameter generation script
load('generate_params_poseidon.sage')
"""
    
    # Write temporary script
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sage', delete=False) as f:
        temp_script = f.name
        f.write(sage_script)
    
    try:
        # Run in Docker
        cmd = [
            'docker', 'run', '--rm',
            '-v', f'{os.getcwd()}:/home/sage/work',
            '-v', f'{temp_script}:/home/sage/run_params.sage',
            'sagemath/sagemath:latest',
            'sage', '/home/sage/run_params.sage'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"SageMath error: {result.stderr}")
            return None
            
        return parse_sage_output(result.stdout)
        
    finally:
        # Clean up temp file
        os.unlink(temp_script)


def parse_sage_output(output):
    """Parse the SageMath output to extract parameters."""
    
    params = {
        'full_rounds': None,
        'partial_rounds': None,
        'round_constants': [],
        'mds_matrix': []
    }
    
    lines = output.split('\n')
    
    # Extract rounds
    for line in lines:
        if 'R_F=' in line:
            match = re.search(r'R_F=(\d+)', line)
            if match:
                params['full_rounds'] = int(match.group(1))
        if 'R_P=' in line:
            match = re.search(r'R_P=(\d+)', line)
            if match:
                params['partial_rounds'] = int(match.group(1))
    
    # Extract round constants
    in_constants = False
    for line in lines:
        if 'Round constants' in line:
            in_constants = True
            continue
        if in_constants and line.strip().startswith('['):
            # Parse the list of constants
            constants_str = line.strip()
            # Extract hex values
            hex_values = re.findall(r"'(0x[0-9a-fA-F]+)'", constants_str)
            params['round_constants'].extend(hex_values)
            in_constants = False
    
    # Extract MDS matrix
    in_mds = False
    mds_lines = []
    for line in lines:
        if 'MDS matrix:' in line:
            in_mds = True
            continue
        if in_mds:
            if line.strip().startswith('['):
                mds_lines.append(line.strip())
                if line.strip().endswith(']]'):
                    # Parse complete MDS matrix
                    matrix_str = ''.join(mds_lines)
                    # Extract rows
                    rows = re.findall(r'\[((?:\'0x[0-9a-fA-F]+\'(?:,\s*)?)+)\]', matrix_str)
                    for row in rows:
                        hex_values = re.findall(r"'(0x[0-9a-fA-F]+)'", row)
                        params['mds_matrix'].append(hex_values)
                    in_mds = False
    
    return params


def generate_rust_file(curve_config, params=None):
    """Generate a Rust parameter file for a curve."""
    
    curve_name = curve_config['name']
    field_type = curve_config['field_type']
    
    # If no params provided, try to load from existing JSON (fallback)
    if params is None:
        json_file = f'poseidon_params_{curve_name}_t{T}_alpha{ALPHA}_M{M}.json'
        if os.path.exists(json_file):
            print(f"  Using existing JSON file: {json_file}")
            with open(json_file, 'r') as f:
                json_data = json.load(f)
                params = {
                    'full_rounds': json_data['metadata']['full_rounds'],
                    'partial_rounds': json_data['metadata']['partial_rounds'],
                    'round_constants': json_data['round_constants'],
                    'mds_matrix': json_data['mds_matrix']
                }
        else:
            print(f"  Warning: No parameters available for {curve_name}")
            return False
    
    # Generate Rust code
    rust_code = f'''// WARNING: This file is auto-generated by generate_parameters.py
// Do not edit this file manually. Regenerate it using the generation script.

//! Poseidon parameters for {curve_name} curve.
//!
//! Auto-generated from the official Poseidon reference implementation
//! with t={T}, α={ALPHA}, M={M} security level.
//!
//! {curve_config['description']}

use light_poseidon::PoseidonParameters;
use lazy_static::lazy_static;

/// Number of full rounds
pub const FULL_ROUNDS: usize = {params['full_rounds']};

/// Number of partial rounds  
pub const PARTIAL_ROUNDS: usize = {params['partial_rounds']};

/// Round constants for {curve_name} (auto-generated)
const ROUND_CONSTANTS: [&str; {len(params['round_constants'])}] = [
'''
    
    # Add round constants
    for rc in params['round_constants']:
        rust_code += f'    "{rc}",\n'
    
    rust_code += '];\n\n'
    
    # Add MDS matrix
    rust_code += f'/// MDS matrix for {curve_name} (auto-generated)\n'
    rust_code += f'const MDS_MATRIX: [[&str; {T}]; {T}] = [\n'
    
    for row in params['mds_matrix']:
        rust_code += '    ['
        for j, elem in enumerate(row):
            rust_code += f'"{elem}"'
            if j < len(row) - 1:
                rust_code += ', '
        rust_code += '],\n'
    
    rust_code += '];\n\n'
    
    # Add lazy static for parameters
    rust_code += f'''lazy_static! {{
    /// Poseidon parameters for {curve_name} {field_type} field (auto-generated)
    pub static ref {curve_name.upper()}_PARAMS: PoseidonParameters<ark_{curve_name}::{field_type}> = {{
        use num_bigint::BigUint;
        
        // Parse round constants
        let mut ark = Vec::new();
        for hex_str in ROUND_CONSTANTS.iter() {{
            let cleaned = hex_str.trim_start_matches("0x");
            let big_int = BigUint::parse_bytes(cleaned.as_bytes(), 16)
                .expect("Failed to parse round constant");
            ark.push(ark_{curve_name}::{field_type}::from(big_int));
        }}
        
        // Parse MDS matrix
        let mut mds = Vec::new();
        for row in MDS_MATRIX.iter() {{
            let mut mds_row = Vec::new();
            for hex_str in row.iter() {{
                let cleaned = hex_str.trim_start_matches("0x");
                let big_int = BigUint::parse_bytes(cleaned.as_bytes(), 16)
                    .expect("Failed to parse MDS matrix element");
                mds_row.push(ark_{curve_name}::{field_type}::from(big_int));
            }}
            mds.push(mds_row);
        }}
        
        PoseidonParameters {{
            ark,
            mds,
            full_rounds: FULL_ROUNDS,
            partial_rounds: PARTIAL_ROUNDS,
            width: {T},
            alpha: {ALPHA},
        }}
    }};
}}

#[cfg(test)]
mod tests {{
    use super::*;
    
    #[test]
    fn test_{curve_name}_params_load() {{
        // Ensure parameters can be loaded
        let params = &*{curve_name.upper()}_PARAMS;
        assert_eq!(params.full_rounds, FULL_ROUNDS);
        assert_eq!(params.partial_rounds, PARTIAL_ROUNDS);
        assert_eq!(params.width, {T});
        assert_eq!(params.alpha, {ALPHA});
    }}
}}
'''
    
    # Write to file
    output_path = Path('src/parameters') / f'{curve_name}.rs'
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write(rust_code)
    
    print(f"  Generated: {output_path}")
    return True


def check_docker():
    """Check if Docker is available."""
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def check_sage_script():
    """Check if the SageMath script exists."""
    return os.path.exists('generate_params_poseidon.sage')


def main():
    print("🎯 Poseidon Parameter Generation Script\n")
    
    # Check prerequisites
    if not check_sage_script():
        print("❌ Error: generate_params_poseidon.sage not found!")
        print("   Please download it from:")
        print("   https://extgit.isec.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_params_poseidon.sage")
        sys.exit(1)
    
    use_docker = check_docker()
    if use_docker:
        print("✅ Docker detected - will generate fresh parameters\n")
    else:
        print("⚠️  Docker not available - will use existing JSON files\n")
    
    # Generate parameters for each curve
    for curve in CURVES:
        print(f"Processing {curve['name'].upper()}...")
        
        params = None
        if use_docker:
            print(f"  Running SageMath for prime: {curve['prime'][:20]}...")
            params = run_sage_in_docker(curve['prime'], f"params_{curve['name']}.txt")
            if params:
                print(f"  Generated: R_F={params['full_rounds']}, R_P={params['partial_rounds']}")
        
        success = generate_rust_file(curve, params)
        if not success and use_docker:
            print(f"  ⚠️  Failed to generate parameters for {curve['name']}")
        
        print()
    
    print("✅ Parameter generation complete!")
    print("\nTo use in your Rust code:")
    print("  use poseidon_hash::parameters::pallas::PALLAS_PARAMS;")
    print("  let hasher = PallasHasher::new_from_ref(&*PALLAS_PARAMS);")


if __name__ == '__main__':
    main()