extern crate argparse;
extern crate ring;
extern crate rpassword;

use argparse::{ArgumentParser, Store};
use ring::aead::*;
use ring::rand::*;
use ring::{aead, digest, pbkdf2};
use std::io::{stdin, stdout, Write};
use std::net::IpAddr;
use std::str::FromStr;

fn main() {
    println!("Hairball - secure p2p messenger\n");
    let config = Config::parse_args();

    let user = User::login();
    println!("Hello {}!", user.username);

    println!("Checking key pair integrity...");
    let message = Message::new(&user, "Hello hairball");
    assert_eq!(message.read(&user), Ok("Hello hairball".to_string()));

    let mut session = Session::new(user, config);
    session.listen_for_messages();
    session.run();
}

#[allow(dead_code)]
struct Config {
    address: IpAddr,
    known_peer: Option<IpAddr>,
}

impl Config {
    fn parse_args() -> Config {
        let mut address = IpAddr::from_str("127.0.0.1").unwrap();
        {
            let mut ap = ArgumentParser::new();
            ap.refer(&mut address)
                .add_option(&["--address"], Store, "Address to connect to");
            ap.parse_args_or_exit();
        }

        Config {
            address,
            known_peer: None,
        }
    }
}

struct User {
    username: String,
    keypair: (OpeningKey, SealingKey),
}

impl User {
    fn login() -> User {
        let mut username = String::new();
        print!("Username: ");
        let _ = stdout().flush();
        let _ = stdin().read_line(&mut username);
        username.pop(); // removing trailing new line character
        let password = rpassword::prompt_password_stdout("Password: ").unwrap();
        let pass_hash = User::hash_password(&username, password);
        let keypair = User::gen_keys(pass_hash);

        User { username, keypair }
    }

    fn hash_password(_username: &str, password: String) -> [u8; 32] {
        let algorithm = &digest::SHA256;
        let mut key = [0; 32];
        // let salt = username.as_bytes();
        let salt = [0, 1, 2, 3, 4, 5, 6, 7];

        pbkdf2::derive(algorithm, 100, &salt, &password.as_bytes(), &mut key);

        key
    }

    fn gen_keys(key: [u8; 32]) -> (OpeningKey, SealingKey) {
        let algorithm = &aead::CHACHA20_POLY1305;
        let opening_key = aead::OpeningKey::new(algorithm, &key).unwrap();
        let sealing_key = aead::SealingKey::new(algorithm, &key).unwrap();

        (opening_key, sealing_key)
    }
}

struct Session {
    user: User,
    config: Config,
    messages: Vec<Message>,
}

impl Session {
    fn new(user: User, config: Config) -> Session {
        Session {
            user,
            config,
            messages: vec![],
        }
    }

    fn run(&mut self) {
        loop {
            print!("> ");
            let _ = stdout().flush();
            let mut input = String::new();
            let _ = stdin().read_line(&mut input);
            let v: Vec<&str> = input.split(' ').collect();

            let mut command = v[0].to_string();
            command.pop();

            match command.as_str() {
                "exit" => break,
                // TODO send message
                // TODO list messages
                // TODO read message
                "?" | "help" | _ => println!("No help yet ¯\\_(ツ)_/¯. Type `exit` to exit.",),
            }
        }
    }

    fn listen_for_messages(&self) {
        // TODO
        // - open tcp connection to peer (config.knownPeer)
        // - spawn thread listening to tcp connection for messages
    }
}

struct Message {
    // TODO should add sender signature
    nonce: Vec<u8>,
    body: Vec<u8>,
}

impl Message {
    fn new(reciever: &User, message: &str) -> Message {
        let mut body = message.as_bytes().to_vec();
        for _ in 0..aead::CHACHA20_POLY1305.tag_len() {
            body.push(0);
        }

        // TODO generate random nonce per encryption
        let mut nonce = vec![0; 12];
        let rand = SystemRandom::new();
        rand.fill(&mut nonce).unwrap();

        // encrypt message body
        match seal_in_place(
            &reciever.keypair.1,
            &nonce,
            &[],
            &mut body,
            aead::CHACHA20_POLY1305.tag_len(),
        ) {
            Ok(_) => {}
            Err(error) => println!("Error: {:?}", error),
        }

        Message {
            // There has to be a nicer way of doing this
            nonce,
            body,
        }
    }

    fn read(&self, reader: &User) -> Result<String, &'static str> {
        let mut body = self.body.clone();

        match open_in_place(&reader.keypair.0, &self.nonce, &[], 0, &mut body) {
            Ok(data) => Ok(String::from_utf8(data.to_vec()).unwrap()),
            Err(_) => Err("error reading message"),
        }
    }
}
