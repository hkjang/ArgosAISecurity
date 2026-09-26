use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "argos-vault",
    version,
    about = "별도 호스트의 서명 수신증명 보관 서버"
)]
struct Args {
    #[arg(long, default_value = "/etc/argos-vault/server.toml")]
    config: PathBuf,
    /// 전용 0700 디렉터리에 새 0600 키를 생성하고 공개키만 출력
    #[arg(long)]
    generate_key: Option<PathBuf>,
}
#[tokio::main]
async fn main() -> argos_vault::Result<()> {
    let args = Args::parse();
    if let Some(path) = args.generate_key {
        let public = argos_vault::generate_signing_key_file(&path)?;
        println!("{public}");
        return Ok(());
    }
    let config = argos_vault::load_server_config(&args.config)?;
    let bind = config.bind;
    let application = argos_vault::router(config)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("Argos 보관 서버 시작: {bind}");
    axum::serve(listener, application).await?;
    Ok(())
}
