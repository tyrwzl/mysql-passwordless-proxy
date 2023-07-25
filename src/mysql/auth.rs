use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::capabilities::{
    CLIENT_DEPRECATE_EOF, CLIENT_INTERACTIVE, CLIENT_LOCAL_FILES, CLIENT_LONG_FLAG,
    CLIENT_LONG_PASSWORD, CLIENT_PROTOCOL_41, CLIENT_QUERY_ATTRIBUTES, CLIENT_SECURE_CONNECTION,
    CLIENT_TRANSACTIONS,
};

struct InitialHandshake<'slice> {
    payload_size: usize,
    auth_plugin_data_part1: &'slice [u8],
    auth_plugin_data_part2: &'slice [u8],
    auth_plugin_name: &'slice [u8],
}

fn parse_initial_handshake(buf: &[u8]) -> InitialHandshake {
    let payload_size = buf[0] as usize + (buf[1] as usize >> 8) + (buf[2] as usize >> 16);

    // skip header
    let mut payload_offset = 4;
    // skip protocol version
    payload_offset += 1;
    let idx = buf[payload_offset..]
        .iter()
        .position(|p| p == &0u8)
        .unwrap();
    // skip server version
    payload_offset += 1 + idx;
    // skip thread id
    payload_offset += 4;

    let auth_plugin_data_part1 = &buf[payload_offset..payload_offset + 8];
    payload_offset += 8;

    // skip filler
    payload_offset += 1;
    // skip capability_flags_1
    payload_offset += 2;
    // skip character_set
    payload_offset += 1;
    // skip status_flags
    payload_offset += 2;
    // skip capability_flags_2
    payload_offset += 2;

    let length_of_plugin_auth_data = buf[payload_offset] as usize;
    payload_offset += 1;

    // reserved 10bytes
    payload_offset += 10;

    let auth_plugin_data_part2 =
        &buf[payload_offset..payload_offset + (length_of_plugin_auth_data - 8)];
    payload_offset += length_of_plugin_auth_data - 8;

    let idx = buf[payload_offset..]
        .iter()
        .position(|p| p == &0u8)
        .unwrap();
    let auth_plugin_name = &buf[payload_offset..payload_offset + idx];

    InitialHandshake {
        payload_size,
        auth_plugin_data_part1,
        auth_plugin_data_part2,
        auth_plugin_name,
    }
}

fn calc_handshake_response(initial_handshake: &InitialHandshake, buf: &mut [u8]) -> usize {
    let mut offset = 0;
    // skip header
    offset += 4;

    let capabilities = (CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_LOCAL_FILES
        | CLIENT_LONG_PASSWORD
        | CLIENT_TRANSACTIONS
        | CLIENT_INTERACTIVE
        | CLIENT_DEPRECATE_EOF
        | CLIENT_QUERY_ATTRIBUTES
        | CLIENT_LONG_FLAG)
        .to_le_bytes();
    buf[offset] = capabilities[0];
    buf[offset + 1] = capabilities[1];
    buf[offset + 2] = capabilities[2];
    buf[offset + 3] = capabilities[3];
    offset += 4;

    // set max_packet_size
    offset += 3;
    buf[offset] = 0x01;
    offset += 1;

    // set character_set
    buf[offset] = 0x2d;
    offset += 1;

    // skip filler
    offset += 23;

    let username = "root".as_bytes();
    buf[offset..offset + username.len()].clone_from_slice(username);
    offset += username.len() + 1;

    // calculate auth_response
    // SHA1( password )
    let password = "password".as_bytes();
    let mut hasher = Sha1::new();
    hasher.update(password);
    let mut auth_response = hasher.finalize();

    // SHA1( SHA1( password ) )
    let mut hasher = Sha1::new();
    hasher.update(auth_response);
    let key2 = hasher.finalize();

    // challenge
    let challenge = [
        initial_handshake.auth_plugin_data_part1,
        &initial_handshake.auth_plugin_data_part2[..12],
    ]
    .concat();

    // SHA1(challenge + SHA1(SHA1(password)))
    let challenge = [challenge, key2.to_vec()].concat();
    let mut hasher = Sha1::new();
    hasher.update(challenge);
    let challenge_key = hasher.finalize();

    // SHA1( password ) XOR SHA1( challenge + SHA1( SHA1( password ) ) )
    for i in 0..20 {
        // XOR
        auth_response[i] ^= challenge_key[i]
    }

    // set auth_response
    buf[offset] = auth_response.len() as u8;
    offset += 1;
    buf[offset..offset + auth_response.len()].clone_from_slice(&auth_response);
    offset += auth_response.len();

    // set auth_plugin_name
    buf[offset..offset + initial_handshake.auth_plugin_name.len()]
        .clone_from_slice(&initial_handshake.auth_plugin_name);
    offset += initial_handshake.auth_plugin_name.len();
    offset += 1;

    // set payload_size
    let payload_size = (offset - 4).to_le_bytes();
    buf[0] = payload_size[0];
    buf[1] = payload_size[1];
    buf[2] = payload_size[2];
    // set sequence_id
    buf[3] = 0x1;

    return offset;
}

pub async fn handle_auth(inbound: &mut TcpStream, outbound: &mut TcpStream) -> std::io::Result<()> {
    // read Initial Handshake from Server
    let mut buf = [0u8; 1024];
    outbound.read(&mut buf).await?;
    let initial_handshake = parse_initial_handshake(&buf);

    // send Initial Handshake to Client
    inbound
        .write(&buf[..initial_handshake.payload_size + 4])
        .await?;

    // read Handshake Response from Client
    let mut buf = [0u8; 1024];
    inbound.read(&mut buf).await?;
    // do nothing, just print
    println!("payload from client: ");
    hexdump::hexdump(&buf[..initial_handshake.payload_size]);

    // send Handshake Response to Server
    let mut buf = [0u8; 1024];
    let offset = calc_handshake_response(&initial_handshake, &mut buf);
    println!("payload to server: ");
    hexdump::hexdump(&buf[..offset]);
    outbound.write(&buf[..offset]).await?;

    // read OK from Server
    let mut response = [0u8; 1024];
    outbound.read(&mut response).await?;
    println!("payload from server: ");
    hexdump::hexdump(&response);

    // send OK to Client
    let response_payload_size =
        response[0] as usize + (response[1] as usize >> 8) + (response[2] as usize >> 16);
    inbound
        .write(&response[0..response_payload_size + 4])
        .await?;

    Ok(())
}
