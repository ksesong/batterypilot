use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn get_output_path() -> PathBuf {
  let manifest_dir_string = env::var("CARGO_MANIFEST_DIR").unwrap();
  let build_type = env::var("PROFILE").unwrap();
  let path = Path::new(&manifest_dir_string)
    .join("target")
    .join(build_type);
  return PathBuf::from(path);
}

fn main() {
  let smc_dir = "src/external/smc-command";
  let target_dir = get_output_path();

  Command::new("make").current_dir(&smc_dir).status().unwrap();

  fs::copy(
    Path::new(&smc_dir).join("smc"),
    Path::new(&target_dir).join("smc"),
  )
  .unwrap();

  Command::new("make")
    .arg("clean")
    .current_dir(&smc_dir)
    .status()
    .unwrap();

  println!("cargo:rerun-if-changed=src/external/smc-command/smc.c");
  println!("cargo:rerun-if-changed=src/external/smc-command/Makefile");
}
