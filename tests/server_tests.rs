use ssh_knock::server::read_tcp_knock;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn ignores_idle_tcp_client_because_one_connection_must_not_block_all_listeners() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let _client = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(250));
    });
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    let mut buffer = [0_u8; 16];
    let started = Instant::now();

    let result = read_tcp_knock(&mut stream, &mut buffer).unwrap();

    assert_eq!(result, None);
    assert!(started.elapsed() < Duration::from_millis(50));
    handle.join().unwrap();
}

#[test]
fn reads_tcp_payload_because_valid_tcp_knocks_must_still_progress() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"knock").unwrap();
    });
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    let mut buffer = [0_u8; 16];

    // Poll like the daemon loop does: the payload may not have arrived on the
    // first non-blocking read, so retry until the bounded deadline.
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut result = None;
    while Instant::now() < deadline {
        if let Some(size) = read_tcp_knock(&mut stream, &mut buffer).unwrap() {
            result = Some(size);
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(result, Some(5));
    assert_eq!(&buffer[..5], b"knock");
    handle.join().unwrap();
}
