# OBS Source Service `obs-service-cargo_audit`

The authoritative source of this project is https://github.com/openSUSE/obs-service-cargo_audit .

`obs-service-cargo_audit` uses the local Cargo.lock file to determine if the related sources in
a Rust application have known security vulnerabilities. If vulnerabilities are found, the source
service will alert allowing you to update and help upstream update their sources.

This relies on having unpacked sources available, so you should use the SCM module.

## Usage for packagers (with SCM service)

1. Add to the `_service` file this snippet:

```
<services>
  <service name="obs_scm" mode="disabled">
    ...
  </service>
  <service name="cargo_audit" mode="disabled">
    <param name="srcdir">projectname</param>
  </service>
</services>
```

2. Run `osc` command locally:

```
$ osc service ra
```

## Manual (without SCM service)

If you are not using SCM, you can use the cargo audit service manually.

1. Extract your source archive into your working directory.

```
$ tar -xv archive.tar.xz
```

2. Examine the folder name it extracted, IE archive-v1.0.0

3. Set srcdir to match

```
<services>
  <service name="cargo_audit" mode="disabled">
    <param name="srcdir">archive-v1.0.0</param>
  </service>
</services>
```

4. Run `osc` command locally:

```
$ osc service ra
```

## Testinc

To test this module directly by hand:

```
python3 path/to/cargo_audit --srcdir /path/to/unpacked/sources
```

## License

MPL-2.0

