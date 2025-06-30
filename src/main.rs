use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};

use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use spl_associated_token_account::instruction as ata_instruction;
use std::str::FromStr;
use tracing_subscriber;

// Response structures
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct AccountMeta2 {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMeta2>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenAccountMeta {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountMeta>,
    instruction_data: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(root))
        .route("/keypair", post(keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "Solana HTTP Server is running!"
}

async fn keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().as_ref()).into_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();

    let response = ApiResponse::success(KeypairResponse { pubkey, secret });
    (StatusCode::OK, Json(response))
}


async fn create_token(Json(payload): Json<CreateTokenRequest>) -> impl IntoResponse {
  
    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error(
                "Invalid mint authority public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error(
                "Invalid mint public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

  
    let rent_sysvar = solana_sdk::sysvar::rent::id();
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None, 
        payload.decimals,
    )
    .unwrap();

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMeta2 {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response_data = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    let response = ApiResponse::success(response_data);
    (StatusCode::OK, Json(response))
}

async fn mint_token(Json(payload): Json<MintTokenRequest>) -> impl IntoResponse {
    // Parse pubkeys
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error(
                "Invalid mint public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error(
                "Invalid destination public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error(
                "Invalid authority public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

  
    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    )
    .unwrap();

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMeta2 {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response_data = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    let response = ApiResponse::success(response_data);
    (StatusCode::OK, Json(response))
}

async fn sign_message(Json(payload): Json<SignMessageRequest>) -> impl IntoResponse {
    // Validate required fields
    if payload.message.is_empty() || payload.secret.is_empty() {
        let response = ApiResponse::<SignMessageResponse>::error(
            "Missing required fields".to_string(),
        );
        return (StatusCode::BAD_REQUEST, Json(response));
    }

   
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = ApiResponse::<SignMessageResponse>::error(
                "Invalid secret key format".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            let response = ApiResponse::<SignMessageResponse>::error(
                "Invalid secret key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Sign the message
    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response_data = SignMessageResponse {
        signature: base64::encode(signature.as_ref()),
        public_key: bs58::encode(keypair.pubkey().as_ref()).into_string(),
        message: payload.message,
    };

    let response = ApiResponse::success(response_data);
    (StatusCode::OK, Json(response))
}

async fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> impl IntoResponse {
    // Parse public key
    let pubkey_bytes = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = ApiResponse::<VerifyMessageResponse>::error(
                "Invalid public key format".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let pubkey = match Pubkey::try_from(&pubkey_bytes[..]) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<VerifyMessageResponse>::error(
                "Invalid public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Parse signature
    let signature_bytes = match base64::decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = ApiResponse::<VerifyMessageResponse>::error(
                "Invalid signature format".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let signature = match Signature::try_from(&signature_bytes[..]) {
        Ok(sig) => sig,
        Err(_) => {
            let response = ApiResponse::<VerifyMessageResponse>::error(
                "Invalid signature".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Verify the signature
    let message_bytes = payload.message.as_bytes();
    let is_valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    let response_data = VerifyMessageResponse {
        valid: is_valid,
        message: payload.message,
        pubkey: payload.pubkey,
    };

    let response = ApiResponse::success(response_data);
    (StatusCode::OK, Json(response))
}

async fn send_sol(Json(payload): Json<SendSolRequest>) -> impl IntoResponse {
    // Validate inputs
    if payload.lamports == 0 {
        let response = ApiResponse::<SendSolResponse>::error(
            "Invalid amount: lamports must be greater than 0".to_string(),
        );
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    // Parse pubkeys
    let from = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendSolResponse>::error(
                "Invalid sender public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let to = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendSolResponse>::error(
                "Invalid recipient public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Create transfer instruction
    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    let response_data = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect(),
        instruction_data: base64::encode(&instruction.data),
    };

    let response = ApiResponse::success(response_data);
    (StatusCode::OK, Json(response))
}

async fn send_token(Json(payload): Json<SendTokenRequest>) -> impl IntoResponse {
    // Validate inputs
    if payload.amount == 0 {
        let response = ApiResponse::<SendTokenResponse>::error(
            "Invalid amount: amount must be greater than 0".to_string(),
        );
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    // Parse pubkeys
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendTokenResponse>::error(
                "Invalid mint public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendTokenResponse>::error(
                "Invalid destination public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendTokenResponse>::error(
                "Invalid owner public key".to_string(),
            );
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Calculate associated token accounts
    let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let dest_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);

    // Create transfer instruction
    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        payload.amount,
    )
    .unwrap();

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| SendTokenAccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    let response_data = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    let response = ApiResponse::success(response_data);
    (StatusCode::OK, Json(response))
}