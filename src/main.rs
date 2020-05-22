use actix_web::{web, App, HttpServer, Responder, middleware, Error, FromRequest};
use clamav;
use clamav::{db, engine, scan_settings};
use std::sync::{Arc};
use awmp;
use std::process::Command;
use serde_derive::Serialize;

#[derive(Clone)]
pub struct Scanner {
    scanner: Arc<engine::Engine>,
    settings: Arc<scan_settings::ScanSettings>,
}

#[derive(Serialize)]
struct ScanResult {
    malicious: bool,
    result: String,
}

async fn index() -> impl Responder {
    "Post file to scan"
}

async fn scan(scanner: web::Data<Scanner>, parts: awmp::Parts) -> Result<web::Json<ScanResult>, Error> {
    let file = parts.files
        .into_inner()
        .into_iter()
        .filter(|(k, _)| k.as_str() == "file")
        .map(|(_, v)| v.unwrap())
        .next()
        .unwrap();

    let path = file.persist("/tmp").unwrap();
	let result = scanner.scanner
        .scan_file(path.to_str().unwrap(), &scanner.settings)
        .expect("this scan better work");
	
	let body = match result {
    	engine::ScanResult::Virus(name) => ScanResult { malicious: true, result: name },
    	engine::ScanResult::Clean => ScanResult { malicious: false, result: "clean".to_string() },
    	engine::ScanResult::Whitelisted => ScanResult { malicious: false, result: "whitelisted".to_string() },
	};

    Ok(web::Json(body))
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web_v2=info");

    //update clamav
    println!("Updating signatures...");
    let _output = Command::new("freshclam")
        .args(&["-F"])
        .output()
        .expect("failed to update sigs");
    println!("Done updating signatures.");

    //initialize clamav
    clamav::initialize().expect("initialize failed");
    let scanner = engine::Engine::new();
    scanner.load_databases(&db::default_directory()).expect("load failed");
    scanner.compile().expect("compile failed");
    let settings: scan_settings::ScanSettings = Default::default();
    let s = Scanner { scanner: Arc::new(scanner), settings: Arc::new(settings)} ;

    // start HTTP server
    HttpServer::new(move || {
        App::new().data(s.clone())
            .data(awmp::Parts::configure(|cfg| cfg.with_file_limit(1024*1024*50)))
            .wrap(middleware::Logger::default())
            .service(web::resource("/file/scan")
				.route(web::get().to(index))
            	.route(web::post().to(scan)))
    })
    .bind("0.0.0.0:8000")?
    .run()
    .await
}
