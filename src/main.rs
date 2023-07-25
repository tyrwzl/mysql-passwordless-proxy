use mysql_passwordless_proxy::mysql::auth::handle_auth;
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listen_addr = "127.0.0.1:3306";
    let server_addr = "127.0.0.1:3307";

    println!("Listening on: {}", listen_addr);
    println!("Proxying to: {}", server_addr);

    let listener = TcpListener::bind(listen_addr).await?;
    while let Ok((mut inbound, _)) = listener.accept().await {
        let mut outbound = TcpStream::connect(server_addr).await?;

        // handle authentication
        handle_auth(&mut inbound, &mut outbound).await?;
        match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
            Ok((to_egress, to_ingress)) => {
                println!(
                    "Connection ended gracefully ({to_egress} bytes from client, {to_ingress} bytes from server)"
                );
            }
            Err(err) => {
                println!("Error while proxying: {}", err);
            }
        }
    }

    Ok(())
}
