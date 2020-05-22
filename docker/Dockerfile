from rust:1.43.1

RUN useradd -ms /bin/bash clamav
RUN apt-get update -y && apt-get install -y libclamav9 clamav-freshclam

WORKDIR /usr/src/app

# build deps
COPY Cargo.toml Cargo.lock /usr/src/app/
COPY docker/dummy.rs /usr/src/app/src/main.rs
RUN cargo build --release

# build application
COPY src/main.rs /usr/src/app/src/main.rs
RUN cargo install --release --path .

EXPOSE 8000
CMD ["/usr/src/app/clamav-rest.debug"]
