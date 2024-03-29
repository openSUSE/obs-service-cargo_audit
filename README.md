# OBS Source Service `obs-service-cargo_audit`

The authoritative source of this project is https://github.com/openSUSE/obs-service-cargo_audit .

`obs-service-cargo_audit` uses the local Cargo.lock file to determine if the related sources in
a Rust application have known security vulnerabilities. If vulnerabilities are found, the source
service will alert allowing you to update and help upstream update their sources.

It is prefered that you use an SCM service for srcdir to exist, but alternately this can
unpack your sources for scanning.

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

## Usage for packagers (with OUT SCM service)

1. Add to the `_service` file this snippet:

```
<services>
  <service name="cargo_audit" mode="disabled">
  </service>
</services>
```

2. Run `osc` command locally:

```
$ osc service ra
```

## Manual (without obs services configured)

1. Run `osc` command locally in your checked out obs package.

```
$ osc service lr cargo_audit
```

## To use a specific lockfile

Some projects ship multiple Cargo.lock files, in some cases with intentionally vulnerable content.
Rustsec does this for example to test that they can find these vulnerabilities.

In these cases you may wish to set a lockfile to scan. This is relative to your unpacked sources
or srcdir.

### SCM

```
<services>
  <service name="obs_scm" mode="disabled">
    ...
  </service>
  <service name="cargo_audit" mode="disabled">
    <param name="srcdir">projectname</param>
    <param name="lockfile">Cargo.lock</param>
  </service>
</services>
```

### Source Unpacking

```
<services>
  <service name="cargo_audit" mode="disabled">
    <param name="lockfile">projectname-0.7.2/Cargo.lock</param>
  </service>
</services>
```

## Testing

To test this module directly by hand:

```
python3 path/to/cargo_audit
python3 path/to/cargo_audit --srcdir=/path/to/unpacked/sources
python3 path/to/cargo_audit --srcdir=/path/to/unpacked/sources --lockfile=path/to/Cargo.lock
python3 path/to/cargo_audit --lockfile=path/to/Cargo.lock
```

To get further debugging info, run with:

```
DEBUG=1 python3 path/to/cargo_audit
```

## Do Scan

In some cases we may wish to scan the complete set of packages that OBS has that
rely on rust for vulnerabilities. This is what the "do\_scan" utility achieves.

> WARNING: This may consume a large amount of disk or CPU to run this tool.

```
python3 do_scan.py
```

If you have already run this, and want to just re-check security advisories
for already setup sources:

```
python3 do_scan.py --assume-setup
```

To scan which packages are affected by a specific vulnerability

```
python3 do_scan.py --assume-setup --rustsec-id XXXX
```

You can scan specific packages with `--package`.

```
python3 do_scan.py --package a b c
```

To scan a different OBS instance you can set the url and repo name

```
python3 do_scan.py --api https://api.opensuse.org --repo openSUSE:Factory
```

## License

MPL-2.0

