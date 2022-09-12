#!/usr/bin/python3
import subprocess
import argparse
import os
import xml.etree.ElementTree as ET
import tarfile
import sys
import json

# Import Crimes
import importlib.machinery
import importlib.util
loader = importlib.machinery.SourceFileLoader( 'cargo_audit_module', './cargo_audit' )
spec = importlib.util.spec_from_loader( 'cargo_audit_module', loader )
cargo_audit_module = importlib.util.module_from_spec( spec )
loader.exec_module( cargo_audit_module )

EXCLUDE = set([
    # ALready cared for
    'MozillaFirefox',
    'MozillaThunderbird',
    'rust',
    # Doesn't have any true rust deps.
    'obs-service-cargo_audit',
    'cargo-audit-advisory-db',
    'rust-packaging',
    # Dead
    'seamonkey',
    'meson:test',
])

def list_whatdepends(obs_api, obs_repo):
    # osc whatdependson openSUSE:Factory rust standard x86_64
    raw_depends = subprocess.check_output(
        [
            "osc",
            "-A", obs_api,
            "whatdependson",
            obs_repo,
            "rust",
            "standard",
            "x86_64"
        ],
        encoding='UTF-8')

    # Split on new lines
    raw_depends = raw_depends.split('\n')

    # First line is our package name, so remove it.
    raw_depends = raw_depends[1:]

    # Clean up white space now.
    raw_depends = [x.strip() for x in raw_depends]

    # Remove any empty strings.
    raw_depends = [x for x in raw_depends if x != '']

    # remove anything that ends with :term, since this is a multi-build and generally used in tests
    raw_depends = [x for x in raw_depends if len(x.split(':')) == 1]

    # Do we have anything that we should exclude?
    raw_depends = [x for x in raw_depends if x not in EXCLUDE]

    return raw_depends

def get_develproject(pkgname, obs_api, obs_repo):
    print(f"intent to scan - {obs_repo}/{pkgname}")
    try:
        out = subprocess.check_output(["osc", "-A", obs_api, "dp", f"{obs_repo}/{pkgname}"])
    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve develproject information for {obs_repo}/{pkgname}")
        print(e.stdout)
        raise e
    return out.decode('UTF-8').strip()

def checkout_or_update(pkgname, should_setup, obs_api, obs_repo):
    try:
        if os.path.exists(obs_repo) and os.path.exists(f'{obs_repo}/{pkgname}'):
            print(f"osc -A {obs_api} revert {obs_repo}/{pkgname}")
            # Revert/cleanup if required.
            out = subprocess.check_output(["osc", "-A", obs_api, "revert", "."], cwd=f"{obs_repo}/{pkgname}")
            print(f"osc -A {obs_api} clean {obs_repo}/{pkgname}")
            out = subprocess.check_output(["osc", "-A", obs_api, "clean", "."], cwd=f"{obs_repo}/{pkgname}")
            if should_setup:
                print(f"osc -A {obs_api} up {obs_repo}/{pkgname}")
                out = subprocess.check_output(["osc", "-A", obs_api, "up", f"{obs_repo}/{pkgname}"])
        elif should_setup:
            print(f"osc -A {obs_api} co {obs_repo}/{pkgname}")
            out = subprocess.check_output(["osc", "-A", obs_api, "co", f"{obs_repo}/{pkgname}"])
        else:
            print(f"Nothing to do")
    except subprocess.CalledProcessError as e:
        print(f"Failed to checkout or update {obs_repo}/{pkgname}")
        print(e.stdout)
        raise e
    # Done!

def does_have_cargo_audit(pkgname, obs_repo):
    service = f"{obs_repo}/{pkgname}/_service"
    if os.path.exists(service):
        has_audit = False
        has_vendor = False
        has_vendor_update = False
        lockfile = None
        tree = ET.parse(service)
        root_node = tree.getroot()
        for tag in root_node.findall('service'):
            if tag.attrib['name'] == 'cargo_audit':
                has_audit = True
                for attr in tag:
                    if attr.attrib['name'] == 'lockfile':
                        lockfile = attr.text
                # We temporarily remove this since we trigger cargo_audit manually
                # from our internal calls.
                root_node.remove(tag)
            if tag.attrib['name'] == 'cargo_vendor':
                has_vendor = True
                for attr in tag:
                    if attr.attrib['name'] == 'update' and attr.text == 'true':
                        has_vendor_update = True
                # Now we temporarily remove this, that way we don't false-negative
                # on vulns.
                root_node.remove(tag)
        tree.write(service)
        return (True, has_audit, has_vendor, has_vendor_update, lockfile)
    return (False, False, False, False, None)

def do_services(pkgname, obs_api, obs_repo):
    cmd = [
        "nsjail",
        "--really_quiet",
        "--config", "scan.cfg",
        "--cwd", f"{os.getcwd()}/{obs_repo}/{pkgname}",
        "--bindmount", f"{os.getcwd()}:{os.getcwd()}",
        "--", "/usr/bin/osc", "-A", obs_api, "service", "ra"
    ]
    try:
        out = subprocess.check_output(cmd, encoding='UTF-8', stderr=subprocess.STDOUT)
        print(f"✅ -- services passed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"🚨 -- services failed")
        print(" ".join(cmd))
        print(e.stdout)
        return False

def do_unpack_scan(pkgname, lockfile, rustsec_id, obs_repo):
    try:
        scan = cargo_audit_module.do_cargo_audit(
            f"{os.getcwd()}/{obs_repo}/{pkgname}",
            None,
            lockfile)
    except Exception as e:
        print(f"🚨 -- cargo_audit was unable to be run - {e}")
        return False

    if rustsec_id is not None:
        affected = False
        for report in scan:
            for advisory in report["vulnerabilities"]["list"]:
                if advisory["advisory"]["id"] == rustsec_id:
                    affected = True
        if not affected:
            print(f"✅ -- NOT affected by {rustsec_id}")
            return True
        else:
            print(f"🚨 -- affected by {rustsec_id}")
            return False
    else:
        if len(scan) == 0:
            print(f"✅ -- cargo_audit passed")
            return True
        else:
            print(f"🚨 -- cargo_audit failed")
            return False

if __name__ == '__main__':
    print("Started OBS cargo audit scan ...")

    parser = argparse.ArgumentParser(
        description="scan OBS gooderer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-a', '--api', dest='obs_api', default="https://api.opensuse.org")
    parser.add_argument('-r', '--repo', dest='obs_repo', default="openSUSE:Factory")
    parser.add_argument('--assume-setup', dest='should_setup', action='store_false')
    parser.add_argument('--rustsec-id', dest='rustsec_id', default=None)
    parser.add_argument('--package', dest='package', default=None, nargs='*')
    args = parser.parse_args()

    if args.package is not None:
        depends = args.package
    else:
        depends = list_whatdepends(args.obs_api, args.obs_repo)

    devel_projects = {}
    for pkgname in depends:
        devel_projects[pkgname] = get_develproject(pkgname, args.obs_api, args.obs_repo)
    lockfiles = {}

    # Check them out, or update if they exist.
    auditable_depends = []
    unpack_depends = []
    need_vendor_services = set()
    maybe_vuln = set()

    for pkgname in depends:
        print("---")
        checkout_or_update(pkgname, args.should_setup, args.obs_api, args.obs_repo)
        # do they have cargo_audit as a service? Could we consider adding it?
        (has_services, has_audit, has_vendor, has_vendor_update, lockfile) = does_have_cargo_audit(pkgname, args.obs_repo)
        lockfiles[pkgname] = lockfile

        if not has_vendor:
            print(f"😭  {args.obs_repo}/{pkgname} missing cargo_vendor service + update - the maintainer should be contacted to add this")
            need_vendor_services.add(f"{devel_projects[pkgname]}/{pkgname}")

        if not has_vendor_update:
            print(f"👀  {args.obs_repo}/{pkgname} missing cargo_vendor auto update - the maintainer should be contacted to add this")

        if not has_audit:
            print(f"⚠️   {args.obs_repo}/{pkgname} missing cargo_audit service - the maintainer should be contacted to add this")
            # print(f"✉️   https://build.opensuse.org/package/users/openSUSE:Factory/{pkgname}")
            # If not, we should contact the developers to add this. We can attempt to unpack
            # and run a scan still though.
            unpack_depends.append((pkgname, has_services))
        else:
            # If they do, run services. We may not know what they need for this to work, so we
            # have to run the full stack, but at the least, the developer probably has this
            # working.
            auditable_depends.append(pkgname)

    if args.should_setup:
        for pkgname in auditable_depends:
            print("---")
            print(f"🛠  running services for {devel_projects[pkgname]}/{pkgname} ...")
            do_services(pkgname, args.obs_api, args.obs_repo)

        for (pkgname, has_services) in unpack_depends:
            print("---")
            if has_services:
                print(f"🛠  running services for {devel_projects[pkgname]}/{pkgname} ...")
                do_services(pkgname, args.obs_api, args.obs_repo)

    # Do the thang
    for pkgname in depends:
        print("---")
        print(f"🍿 unpacking and scanning {devel_projects[pkgname]}/{pkgname} ...")
        lockfile = lockfiles.get(pkgname, None)
        if not do_unpack_scan(pkgname, lockfile, args.rustsec_id, args.obs_repo):
            maybe_vuln.add(f"{devel_projects[pkgname]}/{pkgname}")

    slow_update = maybe_vuln & need_vendor_services
    fast_update = maybe_vuln - slow_update
    # We will warn about these anyway since they are in the vuln set.
    need_vendor_services -= maybe_vuln
    # Remove items which items can rapid-update from the slow set
    maybe_vuln -= fast_update

    print("--- complete")

    if len(fast_update) > 0:
        if args.rustsec_id:
            print(f"- the following pkgs need SECURITY updates to address {args.rustsec_id} - svc setup")
        else:
            print("- the following pkgs need SECURITY updates - svc setup")
        for item in fast_update:
            print(f"osc -A {args.obs_api} bco {item}")

        print(f" Alternately")
        print(f" python3 do_bulk_update.py --yolo %s" % ' '.join(fast_update))


    if len(slow_update) > 0:
        if args.rustsec_id:
            print(f"- the following pkgs need SECURITY updates to address {args.rustsec_id} - manual, missing cargo_vendor")
        else:
            print("- the following pkgs need SECURITY updates - manual")
        for item in slow_update:
            print(f"osc -A {args.obs_api} bco {item}")

    if len(need_vendor_services) > 0:
        print("- the following are NOT vulnerable but SHOULD have services updated to include cargo_vendor!")
        for item in need_vendor_services:
            print(f"osc -A {args.obs_api} bco {item}")



