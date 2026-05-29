use std::{env, process::ExitCode};

use sdqp_audit::{read_replica_file, verify_replica};

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: sdqp-audit-verify <replica-path>");
        return ExitCode::from(2);
    };

    let replica = match read_replica_file(&path) {
        Ok(replica) => replica,
        Err(error) => {
            eprintln!("failed to read replica: {error}");
            return ExitCode::from(1);
        }
    };

    if !verify_replica(&replica) {
        eprintln!("audit replica verification failed");
        return ExitCode::from(1);
    }

    println!(
        "audit replica verified: events={}, checkpoints={}",
        replica.events.len(),
        replica.checkpoints.len()
    );
    ExitCode::SUCCESS
}
