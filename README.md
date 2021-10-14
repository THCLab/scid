# scid

After running `cargo build` in project directory, `scid` can be found in `target/debug` folder.

```
SCID 1.0

USAGE:
    scid [SUBCOMMAND]

FLAGS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    help      Print this message or the help of the given subcommand(s)
    gen       Generate keypair
    sign      Sign data with given private key
    verify    Verify signature with given public key
```

### Usage example

* generate keypair

	```cargo run -- gen -ko keys```

  Saves public key represented by Basic Prefix and private key encoded in base 64 in `keys` file.

  Example of keys saved in file:
  ```
  DZR795ZUyebNH3QJADM7RUGeIPl7HQfI3Y0zpsvU0z3s
  aopeLqPMn2kml_DYlSMJOgfrx4WoN_zfrdlkTEyI9P0=
  ```

* sign data with private key encoded in `base64`. Returns signature represented as Self Signing Prefix

	``` cargo run -- sign -d hello -k $(tail -1 keys) > signature```
  
	example of sign output: 
	`
	0BmHvre9Vhex85Yvtq5FpoDprSZrUE1EM-bbsd72jrggEvUWfptXJ2iqUfLEoR8gJnrD98vFWZIdEP5IO_Ta_6Bw
	`

* verify signature represented as Self Adressing Prefix with public key represented as Basic Prefix

	``` cargo run -- verify -s $(cat signature) -d hello -k $(head -1 keys)```
