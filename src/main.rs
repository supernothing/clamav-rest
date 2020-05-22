use actix_web::{web, App, HttpRequest, HttpServer, Responder, middleware, Error, HttpResponse, FromRequest};
use clamav;
use clamav::{db, engine, scan_settings};
use std::sync::{Arc};
use awmp;

#[derive(Clone)]
pub struct Scanner {
    scanner: Arc<engine::Engine>,
    settings: Arc<scan_settings::ScanSettings>,
}


async fn index(req: HttpRequest) -> impl Responder {
    "Post a file to scan"
}

async fn scan(scanner: web::Data<Scanner>, req: HttpRequest, mut parts: awmp::Parts) -> Result<HttpResponse, Error> {
    let file = parts.files.into_inner().into_iter().filter(|(k, _)| k.as_str() == "file").map(|(_, v)| v.unwrap()).next().unwrap();
    let path = file.persist("/tmp").unwrap();
	let result = scanner.scanner.scan_file(path.to_str().unwrap(), &scanner.settings).expect("this scan better work");
	
	let body = match result {
    	engine::ScanResult::Virus(name) => format!("Virus {}", name),
    	engine::ScanResult::Clean => format!("Clean"),
    	engine::ScanResult::Whitelisted => format!("Whitelisted file")
	};

    Ok(HttpResponse::Ok().body(body))
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web_v2=info");
    clamav::initialize().expect("initialize failed");
    let scanner = engine::Engine::new();
    scanner.load_databases(&db::default_directory()).expect("load failed");
    scanner.compile().expect("compile failed");
    let settings: scan_settings::ScanSettings = Default::default();
    let s = Scanner { scanner: Arc::new(scanner), settings: Arc::new(settings)} ;
    HttpServer::new(move || {
        App::new().data(s.clone())
            .data(awmp::Parts::configure(|cfg| cfg.with_file_limit(1024*1024*50)))
            .wrap(middleware::Logger::default())
            .service(web::resource("/")
				.route(web::get().to(index))
            	.route(web::post().to(scan)))
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}
