use libsecp256k1::{recover, Message, Signature, RecoveryId};
use tiny_keccak::{Hasher, Keccak};

pub fn eth_message(message: String) -> [u8; 32] {
  let msg = format!(
      "{}{}{}",
      "\x19Ethereum Signed Message:\n",
      message.len(),
      message
  );

  keccak256_hash(msg.as_bytes()).try_into().expect("Correct message")
}

fn public_key_to_address(public_key: [u8; 65]) -> String {
  // Step 1: Hash the public key
  let mut hasher = Keccak::v256();
  let mut hash = [0u8; 32];
  hasher.update(&public_key[1..]);
  hasher.finalize(&mut hash);

  // Step 2: Take the last 20 bytes of the hash
  let address_bytes = &hash[12..];

  // Step 3: Convert the address to a hexadecimal string
  let address_hex = hex::encode(address_bytes);

  // Step 4: Prepend "0x" to the hexadecimal address
  format!("0x{}", address_hex)
}

fn keccak256_hash(bytes: &[u8]) -> Vec<u8> {
  let mut hasher = Keccak::v256();
  hasher.update(bytes);
  let mut resp: [u8; 32] = Default::default();
  hasher.finalize(&mut resp);
  resp.iter().cloned().collect()
}

pub fn verify(public_key: String, signature: String, message: String) -> bool {
  let p_key_decoded = hex::decode(public_key[2..].to_string()).unwrap();
  let sign_decoded = hex::decode(signature[2..].to_string()).unwrap();

  println!("p_key_decoded: {:?}", p_key_decoded);
  println!("sign_decoded: {:?}", &sign_decoded[..64]);

  let sign: [u8; 64] = sign_decoded[..64]
      .try_into()
      .expect("Error: Sign with incorrect length");
      
  let message_decoded = eth_message(message);

  println!("message: {:?}", message_decoded);

  let ctx_message = Message::parse(&message_decoded);
  let ctx_sig = Signature::parse_standard(&sign).expect("signature is valid");
  let recovery_id = sign_decoded[64] as i32;

  println!("signature: {:?}", ctx_sig.serialize());
  println!("rec_id: {}", recovery_id);

  let pubkey = recover(&ctx_message, &ctx_sig, &RecoveryId::parse_rpc(recovery_id as u8).unwrap()).unwrap();

  println!("pubkey: {:?}", pubkey.serialize());
  println!("address: {:?}", public_key_to_address(pubkey.serialize()));

  public_key.to_lowercase() == public_key_to_address(pubkey.serialize()).to_lowercase()

}