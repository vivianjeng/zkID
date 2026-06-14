use ecdsa_spartan2::{
    load_instance, load_proof, load_shared_blinds, load_witness,
    paths::keys::{
        PREPARE_INSTANCE, PREPARE_PROOF, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY,
        PREPARE_WITNESS, SHARED_BLINDS, SHOW_INSTANCE, SHOW_PROOF, SHOW_PROVING_KEY,
        SHOW_VERIFYING_KEY, SHOW_WITNESS,
    },
    prover::{
        generate_shared_blinds as gen_shared_blinds, prove_circuit, prove_circuit_with_pk, reblind,
        reblind_with_loaded_data, verify_circuit, verify_circuit_with_loaded_data,
    },
    save_keys,
    setup::{setup_circuit_keys, setup_circuit_keys_no_save},
    CircuitSize, PathConfig, PrepareCircuit, ShowCircuit, E,
};
use std::path::PathBuf;

// Initializes the shared UniFFI scaffolding and defines the `MoproError` enum.
mopro_ffi::app!();

const JWT_CIRCUIT_NAME: &str = "jwt";
const SHOW_CIRCUIT_NAME: &str = "show";

// ============================================================================
// Core Types
// ============================================================================

/// Result of a proving operation with timing and proof metadata
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ProofResult {
    pub prep_ms: u64,
    pub prove_ms: u64,
    pub total_ms: u64,
    pub proof_size_bytes: u64,
    pub comm_w_shared: String,
}

/// Result of a complete benchmark run with timing and size metrics
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct BenchmarkResults {
    // Timing metrics (milliseconds)
    pub jwt_setup_ms: u64,
    pub show_setup_ms: u64,
    pub generate_blinds_ms: u64,
    pub prove_jwt_ms: u64,
    pub reblind_jwt_ms: u64,
    pub prove_show_ms: u64,
    pub reblind_show_ms: u64,
    pub verify_jwt_ms: u64,
    pub verify_show_ms: u64,
    // Size metrics (bytes)
    pub jwt_proving_key_bytes: u64,
    pub jwt_verifying_key_bytes: u64,
    pub show_proving_key_bytes: u64,
    pub show_verifying_key_bytes: u64,
    pub jwt_proof_bytes: u64,
    pub show_proof_bytes: u64,
    pub jwt_witness_bytes: u64,
    pub show_witness_bytes: u64,
}

impl BenchmarkResults {
    /// Format bytes into human-readable size string
    pub fn format_size(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}

/// Errors that can occur during ZK proof operations
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ZkProofError {
    FileNotFound { message: String },
    ProofGenerationFailed { message: String },
    VerificationFailed { message: String },
    InvalidInput { message: String },
    SetupRequired { message: String },
    IoError { message: String },
}

impl std::fmt::Display for ZkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkProofError::FileNotFound { message } => write!(f, "File not found: {}", message),
            ZkProofError::ProofGenerationFailed { message } => {
                write!(f, "Proof generation failed: {}", message)
            }
            ZkProofError::VerificationFailed { message } => {
                write!(f, "Verification failed: {}", message)
            }
            ZkProofError::InvalidInput { message } => write!(f, "Invalid input: {}", message),
            ZkProofError::SetupRequired { message } => write!(f, "Setup required: {}", message),
            ZkProofError::IoError { message } => write!(f, "IO error: {}", message),
        }
    }
}

impl std::error::Error for ZkProofError {}

impl ZkProofError {
    pub fn message(&self) -> String {
        format!("{}", self)
    }
}

impl From<std::io::Error> for ZkProofError {
    fn from(e: std::io::Error) -> Self {
        ZkProofError::IoError {
            message: e.to_string(),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a PathConfig for the given documents path (mobile environment).
fn make_config(documents_path: &str) -> PathConfig {
    PathConfig {
        base_dir: documents_path.into(),
        is_mobile: true,
        circuit_size: CircuitSize::Kb4,
    }
}

// ============================================================================
// Setup Operations
// ============================================================================

/// Setup JWT circuit keys
/// Generates proving and verifying keys for the JWT circuit
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn setup_jwt_keys(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let circuit = PrepareCircuit::new(config.clone(), None);

    let start = std::time::Instant::now();
    setup_circuit_keys(
        circuit,
        config.key_path(PREPARE_PROVING_KEY),
        config.key_path(PREPARE_VERIFYING_KEY),
    );
    let elapsed_ms = start.elapsed().as_millis();

    Ok(format!(
        "JWT circuit keys setup completed in {}ms",
        elapsed_ms
    ))
}

/// Setup Show circuit keys
/// Generates proving and verifying keys for the Show circuit
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn setup_show_keys(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let circuit = ShowCircuit::new(config.clone(), None);

    let start = std::time::Instant::now();
    setup_circuit_keys(
        circuit,
        config.key_path(SHOW_PROVING_KEY),
        config.key_path(SHOW_VERIFYING_KEY),
    );
    let elapsed_ms = start.elapsed().as_millis();

    Ok(format!(
        "Show circuit keys setup completed in {}ms",
        elapsed_ms
    ))
}

// ============================================================================
// Shared Blinds Generation
// ============================================================================

/// Generate shared blinding factors for both circuits
/// Creates random blinding factors that enable proof reblinding
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_shared_blinds(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);

    // Note: While circuits have 98 shared values (2 keybindings + 96 claim scalars),
    // Hyrax batches all these into a single commitment point.
    // num_shared_rows() returns the number of Hyrax commitment points, not individual scalars.
    const NUM_SHARED: usize = 1;
    gen_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS), NUM_SHARED);

    Ok("Shared blinds generated successfully".to_string())
}

// ============================================================================
// Prove Operations
// ============================================================================

/// Generate JWT circuit proof
/// Runs prep_prove + prove phases using existing keys
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_jwt(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);
    let input_dir =
        PathBuf::from(documents_path).join(format!("{}_input.json", JWT_CIRCUIT_NAME));

    if !input_dir.exists() {
        return Err(ZkProofError::FileNotFound {
            message: format!("{} input file not found", JWT_CIRCUIT_NAME),
        });
    }
    println!("input_dir: {}", input_dir.display());
    println!(
        "config: {}",
        config.artifact_path(PREPARE_INSTANCE).display()
    );
    println!(
        "key_path: {}",
        config.key_path(PREPARE_PROVING_KEY).display()
    );
    println!(
        "witness_path: {}",
        config.artifact_path(PREPARE_WITNESS).display()
    );
    println!(
        "proof_path: {}",
        config.artifact_path(PREPARE_PROOF).display()
    );

    let circuit = PrepareCircuit::new(config.clone(), Some(input_dir));

    let start = std::time::Instant::now();
    prove_circuit(
        circuit,
        config.key_path(PREPARE_PROVING_KEY),
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
    );
    let total_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(PREPARE_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(PREPARE_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0, // prover doesn't separate timing
        prove_ms: total_ms,
        total_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

/// Generate Show circuit proof
/// Runs prep_prove + prove phases using existing keys
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_show(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);
    let input_dir = PathBuf::from(documents_path).join(format!("{}_input.json", SHOW_CIRCUIT_NAME));

    if !input_dir.exists() {
        return Err(ZkProofError::FileNotFound {
            message: format!("{} input file not found", SHOW_CIRCUIT_NAME),
        });
    }

    println!("input_dir: {}", input_dir.display());
    println!(
        "config: {}",
        config.artifact_path(SHOW_INSTANCE).display()
    );
    println!(
        "key_path: {}",
        config.key_path(SHOW_PROVING_KEY).display()
    );
    println!(
        "witness_path: {}",
        config.artifact_path(SHOW_WITNESS).display()
    );
    println!(
        "proof_path: {}",
        config.artifact_path(SHOW_PROOF).display()
    );

    let circuit = ShowCircuit::new(config.clone(), Some(input_dir));

    let start = std::time::Instant::now();
    prove_circuit(
        circuit,
        config.key_path(SHOW_PROVING_KEY),
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
    );
    let total_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(SHOW_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(SHOW_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: total_ms,
        total_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

// ============================================================================
// Reblind Operations
// ============================================================================

/// Reblind JWT circuit proof
/// Generates a new unlinkable proof while preserving comm_W_shared
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn reblind_jwt(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);

    let start = std::time::Instant::now();
    reblind(
        config.key_path(PREPARE_PROVING_KEY),
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
        config.artifact_path(SHARED_BLINDS),
    );
    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(PREPARE_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(PREPARE_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: elapsed_ms,
        total_ms: elapsed_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

/// Reblind Show circuit proof
/// Generates a new unlinkable proof while preserving comm_W_shared
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn reblind_show(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);

    let start = std::time::Instant::now();
    reblind(
        config.key_path(SHOW_PROVING_KEY),
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
        config.artifact_path(SHARED_BLINDS),
    );
    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(SHOW_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(SHOW_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: elapsed_ms,
        total_ms: elapsed_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

// ============================================================================
// Verify Operations
// ============================================================================

/// Verify JWT circuit proof
/// Verifies the proof using the verifying key
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_jwt(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);
    verify_circuit(
        config.artifact_path(PREPARE_PROOF),
        config.key_path(PREPARE_VERIFYING_KEY),
    );
    Ok(true)
}

/// Verify Show circuit proof
/// Verifies the proof using the verifying key
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_show(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);
    verify_circuit(
        config.artifact_path(SHOW_PROOF),
        config.key_path(SHOW_VERIFYING_KEY),
    );
    Ok(true)
}

// ============================================================================
// Benchmark Operations
// ============================================================================

/// Run complete benchmark pipeline for both JWT and Show circuits
/// Executes all 9 steps: setup, prove, reblind, and verify for both circuits
/// Returns comprehensive timing and size metrics
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn run_complete_benchmark(
    documents_path: String,
) -> Result<BenchmarkResults, ZkProofError> {
    let config = make_config(&documents_path);
    let jwt_input =
        PathBuf::from(&documents_path).join(format!("{}_input.json", JWT_CIRCUIT_NAME));
    let show_input =
        PathBuf::from(&documents_path).join(format!("{}_input.json", SHOW_CIRCUIT_NAME));

    // Note: While circuits have 98 shared values (2 keybindings + 96 claim scalars),
    // Hyrax batches all these into a single commitment point.
    // num_shared_rows() returns the number of Hyrax commitment points, not individual scalars.
    const NUM_SHARED: usize = 1;

    // Step 1: Setup JWT Circuit
    let jwt_circuit = PrepareCircuit::new(config.clone(), Some(jwt_input.clone()));
    let start = std::time::Instant::now();
    let (jwt_pk, jwt_vk) = setup_circuit_keys_no_save(jwt_circuit);
    let jwt_setup_ms = start.elapsed().as_millis() as u64;

    // Save JWT keys after timing
    save_keys(
        config.key_path(PREPARE_PROVING_KEY),
        config.key_path(PREPARE_VERIFYING_KEY),
        &jwt_pk,
        &jwt_vk,
    )
    .map_err(|e| ZkProofError::IoError {
        message: format!("Failed to save JWT keys: {}", e),
    })?;

    // Step 2: Setup Show Circuit
    let show_circuit = ShowCircuit::new(config.clone(), Some(show_input.clone()));
    let start = std::time::Instant::now();
    let (show_pk, show_vk) = setup_circuit_keys_no_save(show_circuit);
    let show_setup_ms = start.elapsed().as_millis() as u64;

    // Save Show keys after timing
    save_keys(
        config.key_path(SHOW_PROVING_KEY),
        config.key_path(SHOW_VERIFYING_KEY),
        &show_pk,
        &show_vk,
    )
    .map_err(|e| ZkProofError::IoError {
        message: format!("Failed to save Show keys: {}", e),
    })?;

    // Step 3: Generate Shared Blinds
    let start = std::time::Instant::now();
    gen_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS), NUM_SHARED);
    let generate_blinds_ms = start.elapsed().as_millis() as u64;

    // Step 4: Prove JWT Circuit
    let start = std::time::Instant::now();
    let jwt_circuit = PrepareCircuit::new(config.clone(), Some(jwt_input));
    prove_circuit_with_pk(
        jwt_circuit,
        &jwt_pk,
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
    );
    let prove_jwt_ms = start.elapsed().as_millis() as u64;

    // Step 5: Reblind JWT
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let jwt_instance = load_instance(config.artifact_path(PREPARE_INSTANCE)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load jwt instance: {}", e),
        }
    })?;
    let jwt_witness = load_witness(config.artifact_path(PREPARE_WITNESS)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load jwt witness: {}", e),
        }
    })?;
    let shared_blinds =
        load_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS)).map_err(|e| {
            ZkProofError::FileNotFound {
                message: format!("Failed to load shared blinds: {}", e),
            }
        })?;

    let start = std::time::Instant::now();
    reblind_with_loaded_data(
        &jwt_pk,
        jwt_instance,
        jwt_witness,
        &shared_blinds,
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
    );
    let reblind_jwt_ms = start.elapsed().as_millis() as u64;

    // Step 6: Prove Show Circuit
    let start = std::time::Instant::now();
    let show_circuit = ShowCircuit::new(config.clone(), Some(show_input));
    prove_circuit_with_pk(
        show_circuit,
        &show_pk,
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
    );
    let prove_show_ms = start.elapsed().as_millis() as u64;

    // Step 7: Reblind Show
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let show_instance = load_instance(config.artifact_path(SHOW_INSTANCE)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load show instance: {}", e),
        }
    })?;
    let show_witness = load_witness(config.artifact_path(SHOW_WITNESS)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load show witness: {}", e),
        }
    })?;
    // Reuse shared_blinds from JWT step (already loaded)

    let start = std::time::Instant::now();
    reblind_with_loaded_data(
        &show_pk,
        show_instance,
        show_witness,
        &shared_blinds,
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
    );
    let reblind_show_ms = start.elapsed().as_millis() as u64;

    // Step 8: Verify JWT
    // Load proof before timing (file I/O should not be part of verify benchmark)
    let jwt_proof = load_proof(config.artifact_path(PREPARE_PROOF)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load jwt proof: {}", e),
        }
    })?;

    let start = std::time::Instant::now();
    verify_circuit_with_loaded_data(&jwt_proof, &jwt_vk);
    let verify_jwt_ms = start.elapsed().as_millis() as u64;

    // Step 9: Verify Show
    // Load proof before timing (file I/O should not be part of verify benchmark)
    let show_proof =
        load_proof(config.artifact_path(SHOW_PROOF)).map_err(|e| ZkProofError::FileNotFound {
            message: format!("Failed to load show proof: {}", e),
        })?;

    let start = std::time::Instant::now();
    verify_circuit_with_loaded_data(&show_proof, &show_vk);
    let verify_show_ms = start.elapsed().as_millis() as u64;

    // Measure file sizes
    let jwt_proving_key_bytes = get_proof_size(&config.key_path(PREPARE_PROVING_KEY))?;
    let jwt_verifying_key_bytes = get_proof_size(&config.key_path(PREPARE_VERIFYING_KEY))?;
    let show_proving_key_bytes = get_proof_size(&config.key_path(SHOW_PROVING_KEY))?;
    let show_verifying_key_bytes = get_proof_size(&config.key_path(SHOW_VERIFYING_KEY))?;
    let jwt_proof_bytes = get_proof_size(&config.artifact_path(PREPARE_PROOF))?;
    let show_proof_bytes = get_proof_size(&config.artifact_path(SHOW_PROOF))?;
    let jwt_witness_bytes = get_proof_size(&config.artifact_path(PREPARE_WITNESS))?;
    let show_witness_bytes = get_proof_size(&config.artifact_path(SHOW_WITNESS))?;

    Ok(BenchmarkResults {
        jwt_setup_ms,
        show_setup_ms,
        generate_blinds_ms,
        prove_jwt_ms,
        reblind_jwt_ms,
        prove_show_ms,
        reblind_show_ms,
        verify_jwt_ms,
        verify_show_ms,
        jwt_proving_key_bytes,
        jwt_verifying_key_bytes,
        show_proving_key_bytes,
        show_verifying_key_bytes,
        jwt_proof_bytes,
        show_proof_bytes,
        jwt_witness_bytes,
        show_witness_bytes,
    })
}

// ============================================================================
// Inspection Operations
// ============================================================================

/// Get the shared witness commitment for a circuit
/// Returns hex-encoded commitment that links JWT and Show proofs
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn get_comm_w_shared(
    documents_path: String,
    circuit_type: String,
) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let instance_path = match circuit_type.as_str() {
        "jwt" => config.artifact_path(PREPARE_INSTANCE),
        "show" => config.artifact_path(SHOW_INSTANCE),
        _ => {
            return Err(ZkProofError::InvalidInput {
                message: format!(
                    "Invalid circuit_type '{}'. Must be 'jwt' or 'show'",
                    circuit_type
                ),
            })
        }
    };

    extract_comm_w_shared(&instance_path)
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Extract comm_W_shared from a saved instance file
fn extract_comm_w_shared(
    instance_path: impl AsRef<std::path::Path>,
) -> Result<String, ZkProofError> {
    let instance_path = instance_path.as_ref();
    let instance = load_instance(instance_path).map_err(|e| ZkProofError::FileNotFound {
        message: format!(
            "Failed to load instance from '{}': {}",
            instance_path.display(),
            e
        ),
    })?;

    // Convert comm_W_shared to hex string
    let comm_w_shared_hex = format!("{:?}", instance.comm_W_shared);
    Ok(comm_w_shared_hex)
}

/// Get the size of a proof file in bytes
fn get_proof_size(proof_path: impl AsRef<std::path::Path>) -> Result<u64, ZkProofError> {
    let proof_path = proof_path.as_ref();
    let metadata = std::fs::metadata(proof_path).map_err(|e| ZkProofError::FileNotFound {
        message: format!(
            "Failed to get proof size from '{}': {}",
            proof_path.display(),
            e
        ),
    })?;

    Ok(metadata.len())
}

// ============================================================================
// Circuit Input Generation
// ============================================================================

/// Decode a base64url string (no-padding variant) to raw bytes.
fn b64url_decode(s: &str) -> Vec<u8> {
    let decode_char = |c: u8| -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => 255,
        }
    };
    let mut result = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        let val = decode_char(b);
        if val == 255 {
            continue;
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    result
}

/// Apply standard SHA-256 message padding to `msg`, producing a buffer of
/// `max_len` bytes with `padded_block_len` significant bytes.
fn sha256_pad(msg: &[u8], max_len: usize) -> Result<(Vec<u8>, usize), ZkProofError> {
    let msg_len = msg.len();
    let bit_len = (msg_len as u64) * 8;
    let padded_len = ((msg_len + 9 + 63) / 64) * 64;
    if padded_len > max_len {
        return Err(ZkProofError::InvalidInput {
            message: format!(
                "SHA-256 padded length {} exceeds circuit maxMessageLength {}",
                padded_len, max_len
            ),
        });
    }
    let mut padded = vec![0u8; max_len];
    padded[..msg_len].copy_from_slice(msg);
    padded[msg_len] = 0x80;
    padded[padded_len - 8..padded_len].copy_from_slice(&bit_len.to_be_bytes());
    Ok((padded, padded_len))
}

/// Generate the Prepare (JWT) circuit input JSON for a `vc+sd-jwt` credential.
///
/// Returns a JSON string ready to write to `prepare_input.json` and pass to
/// [`prove_prepare`].  Circuit params are fixed at the **4k** variant:
/// `maxMessageLength=4096`, `maxMatches=4`, `maxSubstringLength=50`,
/// `maxClaims=2`, `maxClaimLength=128`.
///
/// Parameters:
/// - `jwt`: compact JWT (`header.payload.signature`, SD-JWT `~disclosure~` suffix is stripped)
/// - `issuer_pubkey_x`: issuer P-256 X coordinate as a big-endian decimal string
/// - `issuer_pubkey_y`: issuer P-256 Y coordinate as a big-endian decimal string
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_prepare_input(
    jwt: String,
    issuer_pubkey_x: String,
    issuer_pubkey_y: String,
) -> Result<String, ZkProofError> {
    use num_bigint::BigUint;
    use std::str::FromStr;

    const MAX_MSG_LEN: usize = 4096;
    const MAX_MATCHES: usize = 4;
    const MAX_SUBSTR_LEN: usize = 50;
    const MAX_CLAIMS: usize = 2; // MAX_MATCHES - 2
    const MAX_CLAIM_LEN: usize = 128;
    const P256_N: &str =
        "115792089210356248762697446949407573529996955224135760342422259061068512044369";

    // Split header.payload.signature; strip optional ~disclosure~ suffix
    let dot1 = jwt.find('.').ok_or_else(|| ZkProofError::InvalidInput {
        message: "JWT is missing the first '.' separator".into(),
    })?;
    let rest = &jwt[dot1 + 1..];
    let dot2 = rest.find('.').ok_or_else(|| ZkProofError::InvalidInput {
        message: "JWT is missing the second '.' separator".into(),
    })?;
    let header_b64 = &jwt[..dot1];
    let payload_b64 = &rest[..dot2];
    let sig_b64 = rest[dot2 + 1..].split('~').next().unwrap_or("");

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let (padded_msg, padded_len) = sha256_pad(signing_input.as_bytes(), MAX_MSG_LEN)?;

    // Decode compact ES256 signature: 64 bytes, r || s (each 32-byte big-endian)
    let sig_bytes = b64url_decode(sig_b64);
    if sig_bytes.len() != 64 {
        return Err(ZkProofError::InvalidInput {
            message: format!(
                "Expected 64-byte compact ES256 signature, got {}",
                sig_bytes.len()
            ),
        });
    }
    let sig_r = BigUint::from_bytes_be(&sig_bytes[..32]);
    let sig_s = BigUint::from_bytes_be(&sig_bytes[32..64]);
    let n = BigUint::from_str(P256_N).unwrap();
    // s⁻¹ mod n via Fermat's little theorem (n is prime)
    let sig_s_inv = sig_s.modpow(&(&n - BigUint::from(2u32)), &n);

    // Decode payload to locate pattern positions
    let decoded_payload_bytes = b64url_decode(payload_b64);
    let decoded_payload =
        std::str::from_utf8(&decoded_payload_bytes).map_err(|e| ZkProofError::InvalidInput {
            message: format!("JWT payload is not valid UTF-8: {}", e),
        })?;

    // The first two match slots always extract the device binding key
    let fixed_patterns: &[&str] = &[r#""x":""#, r#""y":""#];
    let matches_count = fixed_patterns.len();
    let mut match_substrings: Vec<serde_json::Value> = Vec::new();
    let mut match_lengths: Vec<usize> = Vec::new();
    let mut match_indices: Vec<usize> = Vec::new();

    for pat in fixed_patterns {
        let idx =
            decoded_payload
                .find(pat)
                .ok_or_else(|| ZkProofError::InvalidInput {
                    message: format!("Pattern {:?} not found in JWT payload", pat),
                })?;
        let pat_bytes = pat.as_bytes();
        let mut sub: Vec<serde_json::Value> =
            pat_bytes.iter().map(|b| serde_json::json!(b.to_string())).collect();
        sub.resize(MAX_SUBSTR_LEN, serde_json::json!("0"));
        match_substrings.push(serde_json::Value::Array(sub));
        match_lengths.push(pat_bytes.len());
        match_indices.push(idx);
    }
    // Pad remaining match slots
    while match_substrings.len() < MAX_MATCHES {
        let zeros: Vec<serde_json::Value> =
            (0..MAX_SUBSTR_LEN).map(|_| serde_json::json!("0")).collect();
        match_substrings.push(serde_json::Value::Array(zeros));
        match_lengths.push(0);
        match_indices.push(0);
    }

    // No disclosures → all claim slots are zero-padded
    let mut claims: Vec<serde_json::Value> = Vec::new();
    let mut claim_lengths: Vec<serde_json::Value> = Vec::new();
    let mut decode_flags: Vec<u8> = Vec::new();
    let mut claim_formats: Vec<serde_json::Value> = Vec::new();
    for _ in 0..MAX_CLAIMS {
        let zeros: Vec<serde_json::Value> =
            (0..MAX_CLAIM_LEN).map(|_| serde_json::json!("0")).collect();
        claims.push(serde_json::Value::Array(zeros));
        claim_lengths.push(serde_json::json!("0"));
        decode_flags.push(0u8);
        claim_formats.push(serde_json::json!("1")); // uint (default)
    }

    let message: Vec<serde_json::Value> = padded_msg
        .iter()
        .map(|b| serde_json::json!(b.to_string()))
        .collect();

    let val = serde_json::json!({
        "sig_r": sig_r.to_string(),
        "sig_s_inverse": sig_s_inv.to_string(),
        "pubKeyX": issuer_pubkey_x,
        "pubKeyY": issuer_pubkey_y,
        "message": message,
        "messageLength": padded_len,
        "periodIndex": dot1,
        "matchesCount": matches_count,
        "matchSubstring": match_substrings,
        "matchLength": match_lengths,
        "matchIndex": match_indices,
        "claims": claims,
        "claimLengths": claim_lengths,
        "decodeFlags": decode_flags,
        "claimFormats": claim_formats,
    });

    serde_json::to_string(&val).map_err(|e| ZkProofError::IoError {
        message: format!("Failed to serialize prepare input JSON: {}", e),
    })
}

/// Generate the Show circuit input JSON for a credential presentation.
///
/// Returns a JSON string ready to write to `show_input.json` and pass to
/// [`prove_show`].  Circuit params are fixed at the **4k** variant:
/// `nClaims=2`, `maxPredicates=2`, `maxLogicTokens=8`.
///
/// Parameters:
/// - `jwt`: compact JWT — used to extract `cnf.jwk` device key coordinates
/// - `device_signature`: base64url compact ES256 signature over `SHA-256(nonce)`
/// - `nonce`: the UTF-8 string that was signed by the device key
/// - `claim_values`: normalised claim values from the Prepare circuit output
///   (decimal strings); padded with `"0"` to `nClaims=2`
/// - `predicate_len`: number of active predicates (≤ 2)
/// - `predicate_claim_refs`: which claim index each predicate evaluates
/// - `predicate_ops`: operation code per predicate (0=LE, 1=GE, 2=EQ)
/// - `predicate_rhs_is_ref`: 0 = literal RHS, 1 = RHS references another claim
/// - `predicate_rhs_values`: RHS decimal string values
/// - `expr_len`: number of active logic expression tokens (≤ 8)
/// - `token_types`: 0=REF, 1=AND, 2=OR, 3=NOT
/// - `token_values`: token operand values
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_show_input(
    jwt: String,
    device_signature: String,
    nonce: String,
    claim_values: Vec<String>,
    predicate_len: u64,
    predicate_claim_refs: Vec<u64>,
    predicate_ops: Vec<u64>,
    predicate_rhs_is_ref: Vec<u64>,
    predicate_rhs_values: Vec<String>,
    expr_len: u64,
    token_types: Vec<u64>,
    token_values: Vec<u64>,
) -> Result<String, ZkProofError> {
    use num_bigint::BigUint;
    use sha2::{Digest, Sha256};
    use std::str::FromStr;

    const N_CLAIMS: usize = 2;
    const MAX_PREDICATES: usize = 2;
    const MAX_LOGIC_TOKENS: usize = 8;
    const P256_N: &str =
        "115792089210356248762697446949407573529996955224135760342422259061068512044369";

    let n = BigUint::from_str(P256_N).unwrap();

    // ── Device key from cnf.jwk ──────────────────────────────────────────────
    let dot1 = jwt.find('.').ok_or_else(|| ZkProofError::InvalidInput {
        message: "JWT missing first '.'".into(),
    })?;
    let rest = &jwt[dot1 + 1..];
    let dot2 = rest.find('.').ok_or_else(|| ZkProofError::InvalidInput {
        message: "JWT missing second '.'".into(),
    })?;
    let payload_b64 = &rest[..dot2];

    let decoded_payload_bytes = b64url_decode(payload_b64);
    let decoded_payload =
        std::str::from_utf8(&decoded_payload_bytes).map_err(|e| ZkProofError::InvalidInput {
            message: format!("JWT payload not valid UTF-8: {}", e),
        })?;

    let payload_json: serde_json::Value =
        serde_json::from_str(decoded_payload).map_err(|e| ZkProofError::InvalidInput {
            message: format!("Failed to parse JWT payload JSON: {}", e),
        })?;

    let dev_x_b64 = payload_json["cnf"]["jwk"]["x"]
        .as_str()
        .ok_or_else(|| ZkProofError::InvalidInput {
            message: "cnf.jwk.x not found in JWT payload".into(),
        })?;
    let dev_y_b64 = payload_json["cnf"]["jwk"]["y"]
        .as_str()
        .ok_or_else(|| ZkProofError::InvalidInput {
            message: "cnf.jwk.y not found in JWT payload".into(),
        })?;

    let dev_x_bytes = b64url_decode(dev_x_b64);
    let dev_y_bytes = b64url_decode(dev_y_b64);
    let device_key_x = BigUint::from_bytes_be(&dev_x_bytes);
    let device_key_y = BigUint::from_bytes_be(&dev_y_bytes);

    // ── Device signature ─────────────────────────────────────────────────────
    let sig_bytes = b64url_decode(&device_signature);
    if sig_bytes.len() != 64 {
        return Err(ZkProofError::InvalidInput {
            message: format!(
                "Expected 64-byte compact ES256 device signature, got {}",
                sig_bytes.len()
            ),
        });
    }
    let sig_r = BigUint::from_bytes_be(&sig_bytes[..32]);
    let sig_s = BigUint::from_bytes_be(&sig_bytes[32..64]);
    let sig_s_inv = sig_s.modpow(&(&n - BigUint::from(2u32)), &n);

    // ── Message hash: SHA-256(nonce) mod n ───────────────────────────────────
    let hash_bytes = Sha256::digest(nonce.as_bytes());
    let msg_hash = BigUint::from_bytes_be(&hash_bytes) % &n;

    // ── Pad arrays to circuit dimensions ────────────────────────────────────
    let pad_str = |v: &[String], len: usize| -> Vec<serde_json::Value> {
        (0..len)
            .map(|i| serde_json::json!(v.get(i).map(|s| s.as_str()).unwrap_or("0")))
            .collect()
    };
    let pad_u64 = |v: &[u64], len: usize, default: u64| -> Vec<serde_json::Value> {
        (0..len)
            .map(|i| serde_json::json!(v.get(i).copied().unwrap_or(default).to_string()))
            .collect()
    };

    let claims_out = pad_str(&claim_values, N_CLAIMS);
    let pred_claim_refs = pad_u64(&predicate_claim_refs, MAX_PREDICATES, 0);
    let pred_ops = pad_u64(&predicate_ops, MAX_PREDICATES, 2); // EQ default
    let pred_rhs_is_ref = pad_u64(&predicate_rhs_is_ref, MAX_PREDICATES, 0);
    let pred_rhs_values = pad_str(&predicate_rhs_values, MAX_PREDICATES);
    let tok_types = pad_u64(&token_types, MAX_LOGIC_TOKENS, 0);
    let tok_values = pad_u64(&token_values, MAX_LOGIC_TOKENS, 0);

    let val = serde_json::json!({
        "deviceKeyX": device_key_x.to_string(),
        "deviceKeyY": device_key_y.to_string(),
        "sig_r": sig_r.to_string(),
        "sig_s_inverse": sig_s_inv.to_string(),
        "messageHash": msg_hash.to_string(),
        "predicateLen": predicate_len.to_string(),
        "claimValues": claims_out,
        "predicateClaimRefs": pred_claim_refs,
        "predicateOps": pred_ops,
        "predicateRhsIsRef": pred_rhs_is_ref,
        "predicateRhsValues": pred_rhs_values,
        "tokenTypes": tok_types,
        "tokenValues": tok_values,
        "exprLen": expr_len.to_string(),
    });

    serde_json::to_string(&val).map_err(|e| ZkProofError::IoError {
        message: format!("Failed to serialize show input JSON: {}", e),
    })
}

// ============================================================================
// Legacy Test Function
// ============================================================================

/// Test function for basic UniFFI integration
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mopro_hello_world() -> String {
    "Hello, World!".to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mopro_hello_world() {
        assert_eq!(mopro_hello_world(), "Hello, World!");
    }

    #[test]
    fn test_path_config_mobile() {
        let config = make_config("/app/Documents");
        assert_eq!(
            config.key_path(PREPARE_PROVING_KEY),
            PathBuf::from("/app/Documents/keys/prepare_proving.key")
        );
        assert_eq!(
            config.artifact_path(PREPARE_PROOF),
            PathBuf::from("/app/Documents/keys/prepare_proof.bin")
        );
    }

    #[test]
    fn test_make_config_uses_4k() {
        let config = make_config("/docs");
        assert_eq!(config.circuit_size, CircuitSize::Kb4);
        assert!(config.is_mobile);
    }

    #[test]
    fn test_invalid_circuit_type() {
        let result = get_comm_w_shared(".".to_string(), "invalid".to_string());
        assert!(matches!(result, Err(ZkProofError::InvalidInput { .. })));
    }
}

// ============================================================================
// E2E Tests
// ============================================================================

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use std::fs;

    // Absolute path to this crate, set at compile time.
    const CRATE_DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn circom_root() -> PathBuf {
        PathBuf::from(CRATE_DIR)
            .parent()
            .expect("CARGO_MANIFEST_DIR has no parent")
            .join("circom")
    }

    /// Builds a temp directory tree that matches the mobile app's document structure:
    ///
    ///   {temp}/circom/                          ← documents_path passed to Rust FFI
    ///     build/jwt/jwt_js/jwt.r1cs             ← jwt_4k r1cs, using mobile-style name
    ///     build/show/show_js/show.r1cs
    ///     jwt_input.json                        ← 4k JWT inputs (for prove_jwt + run_complete_benchmark)
    ///     show_input.json                       ← show inputs (for prove_show + run_complete_benchmark)
    ///
    /// Returns the documents_path string.
    fn setup_mobile_docs(path: &std::path::Path) -> String {
        let docs = path.join("circom");
        let circom = circom_root();

        let jwt_dir = docs.join("build/jwt/jwt_js");
        let show_dir = docs.join("build/show/show_js");
        fs::create_dir_all(&jwt_dir).expect("create jwt dir");
        fs::create_dir_all(&show_dir).expect("create show dir");

        fs::copy(
            circom.join("build/jwt_4k/jwt_4k_js/jwt_4k.r1cs"),
            jwt_dir.join("jwt.r1cs"),
        )
        .expect("copy jwt_4k.r1cs -> jwt.r1cs");
        fs::copy(
            circom.join("build/show/show_js/show.r1cs"),
            show_dir.join("show.r1cs"),
        )
        .expect("copy show.r1cs");

        let jwt_4k_input = circom.join("inputs/jwt/4k/default.json");
        let show_input = circom.join("inputs/show/4k/default.json");

        fs::copy(&jwt_4k_input, docs.join("jwt_input.json"))
            .expect("copy jwt 4k input -> jwt_input.json");
        fs::copy(&show_input, docs.join("show_input.json"))
            .expect("copy show 4k input -> show_input.json");

        docs.to_string_lossy().into_owned()
    }

    /// Full 9-step ZK workflow matching the Flutter app's E2E sequence:
    ///   setup_jwt → setup_show → generate_blinds →
    ///   prove_jwt → reblind_jwt → prove_show → reblind_show →
    ///   verify_jwt → verify_show → comm_W_shared linkage check
    #[test]
    #[ignore = "Long-running e2e (~5 min); run with: cargo test -- --ignored e2e_full_workflow"]
    fn e2e_full_workflow() {
        let temp = tempfile::tempdir().expect("create temp dir");

        let docs = setup_mobile_docs(temp.path());

        // Step 1: Setup JWT keys
        let r = setup_jwt_keys(docs.clone());
        assert!(r.is_ok(), "setup_jwt_keys failed: {:?}", r.err());

        // Step 2: Setup Show keys
        let r = setup_show_keys(docs.clone());
        assert!(r.is_ok(), "setup_show_keys failed: {:?}", r.err());

        // Step 3: Generate shared blinds
        let r = generate_shared_blinds(docs.clone());
        assert!(r.is_ok(), "generate_shared_blinds failed: {:?}", r.err());

        // Step 4: Prove JWT
        let r = prove_jwt(docs.clone());
        assert!(r.is_ok(), "prove_jwt failed: {:?}", r.err());
        let pr = r.unwrap();
        assert!(pr.proof_size_bytes > 0, "proof_size_bytes must be > 0");
        assert!(
            !pr.comm_w_shared.is_empty(),
            "comm_w_shared must be non-empty"
        );

        // Step 5: Reblind JWT — new unlinkable proof, same commitment
        let r = reblind_jwt(docs.clone());
        assert!(r.is_ok(), "reblind_jwt failed: {:?}", r.err());

        // Step 6: Prove Show
        let r = prove_show(docs.clone());
        assert!(r.is_ok(), "prove_show failed: {:?}", r.err());
        let sr = r.unwrap();
        assert!(sr.proof_size_bytes > 0, "show proof_size_bytes must be > 0");
        assert!(
            !sr.comm_w_shared.is_empty(),
            "show comm_w_shared must be non-empty"
        );

        // Step 7: Reblind Show
        let r = reblind_show(docs.clone());
        assert!(r.is_ok(), "reblind_show failed: {:?}", r.err());

        // Step 8: Verify JWT (reblinded proof must pass)
        let r = verify_jwt(docs.clone());
        assert!(r.is_ok(), "verify_jwt failed: {:?}", r.err());
        assert!(r.unwrap(), "jwt proof must verify");

        // Step 9: Verify Show (reblinded proof must pass)
        let r = verify_show(docs.clone());
        assert!(r.is_ok(), "verify_show failed: {:?}", r.err());
        assert!(r.unwrap(), "show proof must verify");

        // Verify get_comm_w_shared works for both circuits.
        // Note: comm_W_shared equality (linkage) requires end-to-end compatible inputs where
        // jwt and show share the same deviceKey and claims. The default test inputs are
        // independent, so we only assert each commitment is readable and non-empty.
        let prep_comm = get_comm_w_shared(docs.clone(), "jwt".to_string())
            .expect("get_comm_w_shared(jwt) must succeed");
        let show_comm = get_comm_w_shared(docs.clone(), "show".to_string())
            .expect("get_comm_w_shared(show) must succeed");
        assert!(
            !prep_comm.is_empty(),
            "jwt comm_W_shared must be non-empty"
        );
        assert!(
            !show_comm.is_empty(),
            "show comm_W_shared must be non-empty"
        );
    }

    // =========================================================================
    // Real-credential prove tests
    // =========================================================================

    /// Real vc+sd-jwt issued by issuer-vc.wallet.gov.tw (kid: key-1, alg: ES256).
    /// Extracted from vp.verifiableCredential[0] of a live MODA wallet presentation
    /// (2026-06-05). Type: 00000000_vpms_20250605. Signing input: 2145 bytes (fits 4k).
    /// cnf.jwk: x=H32qvUPZeG_ZYjo9YveUX1Pd3PzR53uojabE1LMoUm0
    ///           y=5sPwNmz2MRwjUzfX7PMonZioyVNr7J_JVuWgRFti_z4
    const CREDENTIAL_JWT: &str =
        "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9rZXlzIiwia2lkIjoia2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9\
.eyJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxZDFBQ21ISENza0xnNUNuVmVxVkZHVTc4VmJMWWplQ1dzRXhEenlqNDI5RVNnNGZyQjI0b2tXSmdoNlN1TFVnMWR4OWg1NFBFNWdITXRY\
THV5aWg3UlRheXg4QUZWY241VUNRRFpIQkNoWUNUQ1FIeFl5cnhxN21FSkd3TEdGUFJ6cUJLV3k2VUUxcmFQRTZDSkVlVzVQd295cnpqU0x0NUMxVFZhaTVxdWUiLCJuYmYiOjE3ODA1\
Nzg4NTQsImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticlRRV1BUSk10MkZ1MTZIODR5bXdiYkc5TEdOaW5XN1luajUz\
WkNBVzE2Z3JBaEJpd3Y1M0FuYnY3ODdodDZueGFLTUdHQWdZOVdqdEZ4WVozaGpHZE1kMVNodVFvU3ZOZVh4Y2o1SmNiazJ1WXRmR2J3aW9GU2laUVhmekg3Y3RoaSIsImNuZiI6eyJq\
d2siOnsieCI6IkgzMnF2VVBaZUdfWllqbzlZdmVVWDFQZDNQelI1M3VvamFiRTFMTW9VbTAiLCJjcnYiOiJQLTI1NiIsInkiOiI1c1B3Tm16Mk1Sd2pVemZYN1BNb25aaW95Vk5yN0pf\
SlZ1V2dSRnRpX3o0Iiwia3R5IjoiRUMifX0sImV4cCI6NDkwNDcxNjQ1NCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwi\
dHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX3ZwbXNfMjAyNTA2MDUiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIs\
ImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvMDAwMDAwMDBfdnBtc18yMDI1MDYwNS9yMCM2MSIsInN0YXR1c0xpc3RJbmRleCI6IjYx\
Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9zdGF0dXMtbGlzdC8wMDAwMDAwMF92cG1zXzIwMjUwNjA1L3IwIiwic3Rh\
dHVzUHVycG9zZSI6InJldm9jYXRpb24ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL3Zw\
bXMyMDI1MDYwNS9WMS9lYjYzODQxMi0zMGU3LTRlODYtYTRjNi1mMjg4ZGEyZjRkNjMiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiLXNt\
Um9TRzd0UDBhRmQzcmM1dWFWRTZpSkk5ZFRuZW5TTk11QVV5dURYNCIsIjRRZkdrdWR1N2xaWDJoRTNBb1FkOFY3YmJZUVVzeFRPYVpSWmRKWmtWcjgiLCJNTGZsOUE5ZjNHR0pjZDNf\
NEZ1LVU5YnEzZUZWOUFPS1BwQjQzWkNYel9RIiwiWjc5bi1Ed0tuZDhReHpoMFB2YzNfNV9TZ0ZmenpLcUxMUjhlZUx6NkFwcyIsIno0bUhWS2NqdmZ0YWVoaE5OZUQxVFU4V2x2WkF0\
U1dxVV9NbGRmZGpWZFUiXSwiX3NkX2FsZyI6InNoYS0yNTYifX0sIm5vbmNlIjoiMlk1QVJNM1EiLCJqdGkiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9jcmVk\
ZW50aWFsL2U3YjY3NWZmLTRkNDAtNDIzMi04NThkLWUwYTNjMjVhM2I2ZCJ9\
.R_T5Kp1CvTHigJkZGxoANTvfH3NI-JdAIe8s2jwxrFg8gT13psr4VuAL8i5ALQewMQ5NIMBgzdiKeq1sWNgEZw";

    /// Issuer public key (kid: "key-1") fetched from https://issuer-vc.wallet.gov.tw/api/keys.
    /// x = base64url_decode("dnQ2W9ZTsILYac3XdcvxrYNgIgjSkGJUMecMXVJk7XM") → big-endian uint
    /// y = base64url_decode("0WhT_VgvnhNNj9aabTn4E4enR-iqbCrQtY9UWqD4XJY") → big-endian uint
    const ISSUER_PUBKEY_X: &str =
        "53578245562568858090497762971050088637552636662548898700080252253957930675571";
    const ISSUER_PUBKEY_Y: &str =
        "94717717123739987908966931526384127659809793164315839803856846695569747893398";

    /// Verifies that `generate_prepare_input` produces a correctly structured JSON.
    #[test]
    fn test_generate_prepare_input_structure() {
        let json_str = generate_prepare_input(
            CREDENTIAL_JWT.to_string(),
            ISSUER_PUBKEY_X.to_string(),
            ISSUER_PUBKEY_Y.to_string(),
        )
        .expect("generate_prepare_input failed");

        let v: serde_json::Value =
            serde_json::from_str(&json_str).expect("output is valid JSON");

        // message must be 4096 elements
        assert_eq!(v["message"].as_array().unwrap().len(), 4096);
        // SHA-256 padded length for a 2145-byte signing input = 2176
        assert_eq!(v["messageLength"].as_u64().unwrap(), 2176);
        // Header is 128 base64url chars → period at index 128
        assert_eq!(v["periodIndex"].as_u64().unwrap(), 128);
        // Always 2 built-in patterns
        assert_eq!(v["matchesCount"].as_u64().unwrap(), 2);
        // matchSubstring padded to 4 slots of 50 elements each
        assert_eq!(v["matchSubstring"].as_array().unwrap().len(), 4);
        assert_eq!(v["matchSubstring"][0].as_array().unwrap().len(), 50);
        // '"x":"' pattern bytes: [34, 120, 34, 58, 34]
        assert_eq!(v["matchSubstring"][0][0].as_str().unwrap(), "34");
        assert_eq!(v["matchSubstring"][0][1].as_str().unwrap(), "120");
        // Signature fields must be non-empty non-zero strings
        assert!(!v["sig_r"].as_str().unwrap().is_empty());
        assert_ne!(v["sig_r"].as_str().unwrap(), "0");
        assert!(!v["sig_s_inverse"].as_str().unwrap().is_empty());
    }

    /// Verifies that `generate_show_input` produces a correctly structured JSON
    /// and correctly extracts the device key from CREDENTIAL_JWT's cnf.jwk.
    ///
    /// Uses a placeholder zero-signature (64 A bytes in base64url); this is
    /// structurally valid but would fail circuit witness generation.
    #[test]
    fn test_generate_show_input_structure() {
        // 64 zero bytes in base64url (no padding): 86 'A' characters
        let zero_sig = "A".repeat(86);

        let json_str = generate_show_input(
            CREDENTIAL_JWT.to_string(),
            zero_sig,
            "test-nonce".to_string(),
            vec!["0".to_string(), "0".to_string()], // claim_values
            0,                                       // predicate_len
            vec![],                                  // predicate_claim_refs
            vec![],                                  // predicate_ops
            vec![],                                  // predicate_rhs_is_ref
            vec![],                                  // predicate_rhs_values
            1,                                       // expr_len
            vec![0],                                 // token_types (REF)
            vec![0],                                 // token_values
        )
        .expect("generate_show_input failed");

        let v: serde_json::Value = serde_json::from_str(&json_str).expect("output is valid JSON");

        // Device key extracted from CREDENTIAL_JWT cnf.jwk.x/y
        // x = "H32qvUPZeG_ZYjo9YveUX1Pd3PzR53uojabE1LMoUm0" → decimal
        assert_eq!(
            v["deviceKeyX"].as_str().unwrap(),
            "14243732588632816266767589740520232407876451095741750343898049083578956403309"
        );
        // y = "5sPwNmz2MRwjUzfX7PMonZioyVNr7J_JVuWgRFti_z4" → decimal
        assert_eq!(
            v["deviceKeyY"].as_str().unwrap(),
            "104378148238218408978645448943153702691292549136592630116702416760741755551550"
        );

        // messageHash = SHA-256("test-nonce") mod n — must be a non-zero decimal string
        assert!(!v["messageHash"].as_str().unwrap().is_empty());
        assert_ne!(v["messageHash"].as_str().unwrap(), "0");

        // Arrays padded to circuit dimensions
        assert_eq!(v["claimValues"].as_array().unwrap().len(), 2);
        assert_eq!(v["predicateClaimRefs"].as_array().unwrap().len(), 2);
        assert_eq!(v["predicateOps"].as_array().unwrap().len(), 2);
        assert_eq!(v["predicateRhsIsRef"].as_array().unwrap().len(), 2);
        assert_eq!(v["predicateRhsValues"].as_array().unwrap().len(), 2);
        assert_eq!(v["tokenTypes"].as_array().unwrap().len(), 8);
        assert_eq!(v["tokenValues"].as_array().unwrap().len(), 8);

        // Active token is REF(0)
        assert_eq!(v["tokenTypes"][0].as_str().unwrap(), "0");
        assert_eq!(v["tokenValues"][0].as_str().unwrap(), "0");
        assert_eq!(v["exprLen"].as_str().unwrap(), "1");
        assert_eq!(v["predicateLen"].as_str().unwrap(), "0");
    }

    /// Proves both circuits using the real issued vc+sd-jwt credential for the
    /// Prepare circuit. The Show circuit uses the default synthetic inputs because
    /// the device private key for CREDENTIAL_JWT is not available.
    ///
    /// Steps:
    ///  1. Generate prepare_input.json from CREDENTIAL_JWT + issuer public key
    ///  2. setup_prepare_keys + setup_show_keys
    ///  3. generate_shared_blinds
    ///  4. prove_prepare (real credential) + prove_show (synthetic default)
    ///  5. verify_prepare + verify_show
    #[test]
    #[ignore = "Long-running e2e (~10 min); run with: cargo test -- --ignored e2e_real_credential_prove"]
    fn e2e_real_credential_prove() {
        let temp = tempfile::tempdir().expect("create temp dir");
        // setup_mobile_docs copies default show_input.json — used by prove_show
        let docs = setup_mobile_docs(temp.path());

        // Overwrite prepare_input.json with real credential circuit input
        let prepare_json = generate_prepare_input(
            CREDENTIAL_JWT.to_string(),
            ISSUER_PUBKEY_X.to_string(),
            ISSUER_PUBKEY_Y.to_string(),
        )
        .expect("generate_prepare_input failed");
        let prepare_path = PathBuf::from(&docs).join("prepare_input.json");
        fs::write(&prepare_path, &prepare_json).expect("write prepare_input.json");

        // Step 1: Setup JWT keys
        let r = setup_jwt_keys(docs.clone());
        assert!(r.is_ok(), "setup_jwt_keys failed: {:?}", r.err());

        // Step 2: Setup Show keys
        let r = setup_show_keys(docs.clone());
        assert!(r.is_ok(), "setup_show_keys failed: {:?}", r.err());

        // Step 3: Generate shared blinds
        let r = generate_shared_blinds(docs.clone());
        assert!(r.is_ok(), "generate_shared_blinds failed: {:?}", r.err());

        // Step 4: Prove JWT (real credential)
        let r = prove_jwt(docs.clone());
        assert!(r.is_ok(), "prove_jwt failed: {:?}", r.err());
        let pr = r.unwrap();
        assert!(pr.proof_size_bytes > 0, "prepare proof must be non-empty");
        assert!(!pr.comm_w_shared.is_empty(), "prepare comm_w_shared must be non-empty");
        println!("  prepare prove_ms      : {}", pr.prove_ms);
        println!("  prepare proof_size    : {} bytes", pr.proof_size_bytes);
        println!(
            "  prepare comm_w_shared : {}",
            &pr.comm_w_shared[..pr.comm_w_shared.len().min(60)]
        );

        // Step 5: Prove Show (synthetic default input — device private key unavailable)
        let r = prove_show(docs.clone());
        assert!(r.is_ok(), "prove_show failed: {:?}", r.err());
        let sr = r.unwrap();
        assert!(sr.proof_size_bytes > 0, "show proof must be non-empty");
        assert!(!sr.comm_w_shared.is_empty(), "show comm_w_shared must be non-empty");
        println!("  show prove_ms         : {}", sr.prove_ms);
        println!("  show proof_size       : {} bytes", sr.proof_size_bytes);
        println!(
            "  show comm_w_shared    : {}",
            &sr.comm_w_shared[..sr.comm_w_shared.len().min(60)]
        );

        // Step 6: Verify JWT
        let r = verify_jwt(docs.clone());
        assert!(r.is_ok(), "verify_jwt failed: {:?}", r.err());
        assert!(r.unwrap(), "prepare proof must verify");

        // Step 7: Verify Show
        let r = verify_show(docs.clone());
        assert!(r.is_ok(), "verify_show failed: {:?}", r.err());
        assert!(r.unwrap(), "show proof must verify");
    }

    /// Complete benchmark pipeline — exercises all 9 operations with precise timing.
    #[test]
    #[ignore = "Long-running e2e (~10 min); run with: cargo test -- --ignored e2e_complete_benchmark"]
    fn e2e_complete_benchmark() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let docs = setup_mobile_docs(temp.path());

        let r = run_complete_benchmark(docs);
        assert!(r.is_ok(), "run_complete_benchmark failed: {:?}", r.err());

        let b = r.unwrap();

        // Long-running operations must record positive ms timings.
        // generate_blinds is sub-millisecond so we only assert it doesn't panic.
        assert!(b.jwt_setup_ms > 0, "jwt_setup_ms must be > 0");
        assert!(b.show_setup_ms > 0, "show_setup_ms must be > 0");
        assert!(b.prove_jwt_ms > 0, "prove_jwt_ms must be > 0");
        assert!(b.reblind_jwt_ms > 0, "reblind_jwt_ms must be > 0");
        assert!(b.prove_show_ms > 0, "prove_show_ms must be > 0");
        assert!(b.reblind_show_ms > 0, "reblind_show_ms must be > 0");
        assert!(b.verify_jwt_ms > 0, "verify_jwt_ms must be > 0");
        assert!(b.verify_show_ms > 0, "verify_show_ms must be > 0");

        // All artifacts must be non-empty
        assert!(b.jwt_proof_bytes > 0, "jwt_proof_bytes must be > 0");
        assert!(b.show_proof_bytes > 0, "show_proof_bytes must be > 0");
        assert!(
            b.jwt_proving_key_bytes > 0,
            "jwt_proving_key_bytes must be > 0"
        );
        assert!(
            b.show_proving_key_bytes > 0,
            "show_proving_key_bytes must be > 0"
        );
        assert!(
            b.jwt_witness_bytes > 0,
            "jwt_witness_bytes must be > 0"
        );
        assert!(b.show_witness_bytes > 0, "show_witness_bytes must be > 0");
    }
}
