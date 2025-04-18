use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use nix::fcntl::{flock, FlockArg};
use nix::sys::socket::{
    sendmsg, ControlMessage, MsgFlags, UnixAddr,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SOCKET_PATH_MAIN: &str = "/var/run/pyroute2/fdpass";
const SOCKET_PATH_SERVER: &str = "/var/run/pyroute2/api";
const LOCK_FILE: &str = "/var/run/pyroute2/plugin-lock";

#[derive(Serialize, Deserialize)]
struct RequestPayload {
    cni: HashMap<String, Value>,
    env: HashMap<String, String>,
    rid: String,
}

#[derive(Serialize, Deserialize)]
struct IpInfo {
    version: String,
    address: String,
}

#[derive(Serialize, Deserialize)]
struct PluginResponse {
    #[serde(rename = "cniVersion")]
    cni_version: String,
    ips: Vec<IpInfo>,
}

fn forward_request_to_server(
    input: RequestPayload,
    namespace_fd: RawFd,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Connect to the server
    let mut stream_sock = UnixStream::connect(SOCKET_PATH_SERVER)?;

    // Pack the init request
    let data = json!({"cni": {"cniVersion": "0.3.1"}});
    let json_data = serde_json::to_vec(&data)?;

    // Send the init request
    stream_sock.write_all(&json_data)?;

    // Receive the response
    let mut buffer = [0u8; 4096];
    let n = stream_sock.read(&mut buffer)?;
    eprintln!("recv init: {}", String::from_utf8_lossy(&buffer[..n]));

    // Parse the response
    let response: HashMap<String, String> = serde_json::from_slice(&buffer[..n])?;

    // Get request id
    let rid = response
        .get("rid")
        .ok_or("Failed to get request ID from response")?;

    // Send the file descriptor
    let sock = UnixDatagram::unbound()?;
    sock.connect(SOCKET_PATH_MAIN)?;
    let sock_fd = sock.as_raw_fd();

    let data_fd = json!({"rid": rid}).to_string().into_bytes();

    if namespace_fd > 0 {
        let cmsg = [ControlMessage::ScmRights(&[namespace_fd])];
        sendmsg(
            sock_fd, 
            &data_fd, 
            &cmsg,
            MsgFlags::empty(), 
            Some(&UnixAddr::new(SOCKET_PATH_MAIN)?)
        )?;
    } else {
        sendmsg(
            sock_fd, 
            &data_fd, 
            &[],
            MsgFlags::empty(), 
            Some(&UnixAddr::new(SOCKET_PATH_MAIN)?)
        )?;
    }

    // Add request id and encode payload
    let mut input_with_rid = input;
    input_with_rid.rid = rid.to_string();
    let payload_bytes = serde_json::to_string_pretty(&input_with_rid)?;

    // Send the main request
    stream_sock.write_all(payload_bytes.as_bytes())?;

    // Get the response
    let mut buffer = [0u8; 4096];
    let n = stream_sock.read(&mut buffer)?;

    Ok(buffer[..n].to_vec())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read from stdin
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    // Open lock file
    let flock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(LOCK_FILE)?;
    
    // Acquire lock
    loop {
        match flock(flock_file.as_raw_fd(), FlockArg::LockExclusiveNonblock) {
            Ok(_) => break,
            Err(_) => sleep(Duration::from_secs(2)),
        }
    }

    // Parse stdin JSON
    let cni_data: HashMap<String, Value> = serde_json::from_slice(&input)?;

    // Collect environment variables
    let mut env_vars = HashMap::new();
    let mut namespace_file: Option<File> = None;
    let mut namespace_fd: RawFd = -1;

    for (key, value) in env::vars() {
        env_vars.insert(key.clone(), value.clone());
        if key == "CNI_NETNS" {
            match File::open(Path::new(&value)) {
                Ok(file) => {
                    namespace_fd = file.as_raw_fd();
                    namespace_file = Some(file);
                }
                Err(err) => {
                    eprintln!("failed to open netns: {}", err);
                }
            }
        }
    }

    if namespace_fd == -1 {
        eprintln!("no CNI_NETNS received");
    }

    let payload = RequestPayload {
        cni: cni_data,
        env: env_vars,
        rid: String::new(), // Will be set in forward_request_to_server
    };

    // Forward the request to the server
    let response_body = forward_request_to_server(payload, namespace_fd)?;

    // Parse the response
    let response: PluginResponse = serde_json::from_slice(&response_body)?;

    // Encode the response and print it
    let output = serde_json::to_string(&response)?;
    flock(flock_file.as_raw_fd(), FlockArg::Unlock)?;
    println!("{}", output);

    // Keep namespace_file in scope until the end
    drop(namespace_file);

    Ok(())
}