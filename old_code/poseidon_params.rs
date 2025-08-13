use light_poseidon::PoseidonParameters;
use serde::{Deserialize, Serialize};
use std::fs;

/// JSON structure matching our generated parameter files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoseidonParamsJson {
    pub metadata: Metadata,
    pub round_constants: Vec<String>,
    pub mds_matrix: Vec<Vec<String>>,
    pub security_validation: SecurityValidation,
    pub curve_info: CurveInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub field_size_bits: u32,
    pub state_size: usize,
    pub alpha: u64,
    pub security_level: u32,
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub total_rounds: usize,
    pub num_sboxes: usize,
    pub num_round_constants: usize,
    pub modulus: Modulus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Modulus {
    pub decimal: String,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityValidation {
    pub algorithm_1: bool,
    pub algorithm_2: bool,
    pub algorithm_3: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurveInfo {
    pub curve_name: String,
    pub description: String,
    pub field_type: String,
    pub applications: Vec<String>,
}

impl PoseidonParamsJson {
    /// Load parameters from JSON file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let params: PoseidonParamsJson = serde_json::from_str(&content)?;
        Ok(params)
    }
}

/// Helper functions to load specific curve parameters
pub mod curves {
    use super::*;
    use num_bigint::BigUint;
    
    /// Helper function to parse hex string to field element
    fn parse_hex_to_field<F: From<BigUint>>(hex_str: &str) -> Result<F, Box<dyn std::error::Error>> {
        let cleaned = hex_str.trim_start_matches("0x");
        let big_int = BigUint::parse_bytes(cleaned.as_bytes(), 16)
            .ok_or("Failed to parse hex string")?;
        Ok(F::from(big_int))
    }

    /// Generic function to load parameters for any field type
    pub fn load_parameters<F: From<BigUint> + ark_ff::PrimeField>(filename: &str) -> Result<PoseidonParameters<F>, Box<dyn std::error::Error>> {
        let json = PoseidonParamsJson::from_file(filename)?;
        
        let mut ark = Vec::new();
        for hex_str in &json.round_constants {
            ark.push(parse_hex_to_field(hex_str)?);
        }

        let mut mds = Vec::new();
        for row in &json.mds_matrix {
            let mut mds_row = Vec::new();
            for hex_str in row {
                mds_row.push(parse_hex_to_field(hex_str)?);
            }
            mds.push(mds_row);
        }

        Ok(PoseidonParameters {
            ark,
            mds,
            full_rounds: json.metadata.full_rounds,
            partial_rounds: json.metadata.partial_rounds,
            width: json.metadata.state_size,
            alpha: json.metadata.alpha,
        })
    }
    
    // Specific curve loader for Pallas base field (currently used)
    
    /// Load Pallas base field parameters (Fq) - used by MultiFieldHasher
    pub fn load_pallas_base_field() -> Result<PoseidonParameters<ark_pallas::Fq>, Box<dyn std::error::Error>> {
        load_parameters("poseidon_params_pallas_t3_alpha5_M128.json")
    }
    
    // Generic loader function is available above for loading any curve parameters
    // Usage: load_parameters::<FieldType>("filename.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_load_json() {
        let json = PoseidonParamsJson::from_file("poseidon_params_bn254_t3_alpha5_M128.json").unwrap();
        
        assert_eq!(json.metadata.field_size_bits, 254);
        assert_eq!(json.metadata.state_size, 3);
        assert_eq!(json.metadata.alpha, 5);
        assert_eq!(json.metadata.full_rounds, 8);
        assert_eq!(json.metadata.partial_rounds, 56);
        assert_eq!(json.round_constants.len(), 192);
        assert_eq!(json.mds_matrix.len(), 3);
        assert_eq!(json.mds_matrix[0].len(), 3);
    }

    #[test] 
    fn test_load_pallas_base_field_parameters() {
        let params = curves::load_pallas_base_field().unwrap();
        
        assert_eq!(params.full_rounds, 8);
        assert_eq!(params.partial_rounds, 56);
        assert_eq!(params.width, 3);
        assert_eq!(params.alpha, 5);
        assert_eq!(params.ark.len(), 192);
        assert_eq!(params.mds.len(), 3);
        assert_eq!(params.mds[0].len(), 3);
    }
}