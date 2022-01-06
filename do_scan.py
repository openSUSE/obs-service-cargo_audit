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

WHATDEPENDS = ["osc", "whatdependson", "openSUSE:Factory", "rust", "standard", "x86_64"]

CHECKOUT = ["osc", "co", "openSUSE:Factory"]
UPDATE = ["osc", "up", "openSUSE:Factory"]

EXCLUDE = set([
    'MozillaFirefox',
    'MozillaThunderbird',
    'rust',
    'rust1.53',
    'seamonkey',
    'meson:test'
])

def list_whatdepends():
    # osc whatdependson openSUSE:Factory rust standard x86_64
    raw_depends = subprocess.check_output(WHATDEPENDS, encoding='UTF-8')

    # Split on new lines
    raw_depends = raw_depends.split('\n')

    # First line is our package name, so remove it.
    raw_depends = raw_depends[1:]

    # Clean up white space now.
    raw_depends = [x.strip() for x in raw_depends]

    # Remove any empty strings.
    raw_depends = [x for x in raw_depends if x != '']

    # Do we have anything that we should exclude?
    raw_depends = [x for x in raw_depends if x not in EXCLUDE]

    return raw_depends

def get_develproject(pkgname):
    try:
        out = subprocess.check_output(["osc", "dp", f"openSUSE:Factory/{pkgname}"])
    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve develproject information for openSUSE:Factory/{pkgname}")
        print(e.stdout)
        raise e
    return out.decode('UTF-8').strip()

def checkout_or_update(pkgname):
    try:
        if os.path.exists('openSUSE:Factory') and os.path.exists(f'openSUSE:Factory/{pkgname}'):
            print(f"osc up openSUSE:Factory/{pkgname}")
            # Revert/cleanup if required.
            out = subprocess.check_output(["osc", "revert", "."], cwd=f"openSUSE:Factory/{pkgname}")
            out = subprocess.check_output(["osc", "clean", "."], cwd=f"openSUSE:Factory/{pkgname}")
            out = subprocess.check_output(["osc", "up", f"openSUSE:Factory/{pkgname}"])
        else:
            print(f"osc co openSUSE:Factory/{pkgname}")
            out = subprocess.check_output(["osc", "co", f"openSUSE:Factory/{pkgname}"])
    except subprocess.CalledProcessError as e:
        print(f"Failed to checkout or update openSUSE:Factory/{pkgname}")
        print(e.stdout)
        raise e
    print(f"done")

def does_have_cargo_audit(pkgname):
    service = f"openSUSE:Factory/{pkgname}/_service"
    if os.path.exists(service):
        has_audit = False
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
                for attr in tag:
                    if attr.attrib['name'] == 'update' and attr.text == 'true':
                        has_vendor_update = True
                # Now we temporarily remove this, that way we don't false-negative
                # on vulns.
                root_node.remove(tag)
        tree.write(service)
        return (True, has_audit, has_vendor_update, lockfile)
    return (False, False, False, None)

def do_services(pkgname):
    cmd = [
        "nsjail",
        "--really_quiet",
        "--config", "scan.cfg",
        "--cwd", f"{os.getcwd()}/openSUSE:Factory/{pkgname}",
        "--bindmount", f"{os.getcwd()}:{os.getcwd()}",
        "/usr/bin/osc", "service", "ra"
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

def do_unpack_scan(pkgname, lockfile, rustsec_id):
    try:
        scan = cargo_audit_module.do_cargo_audit(
            f"{os.getcwd()}/openSUSE:Factory/{pkgname}",
            None,
            lockfile)
    except:
        print(f"🚨 -- cargo_audit was unable to be run")
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
    parser.add_argument('--assume-setup', dest='should_setup', action='store_false')
    parser.add_argument('--rustsec-id', dest='rustsec_id', default=None)
    args = parser.parse_args()

    depends = list_whatdepends()

    # For testing, we hardcode the list for dev.
    # depends = ["kanidm", "389-ds", "bottom", "helvum"]

    devel_projects = {}
    for pkgname in depends:
        devel_projects[pkgname] = get_develproject(pkgname)
    lockfiles = {}

    # Check them out, or update if they exist.
    auditable_depends = []
    unpack_depends = []
    need_services = set()
    maybe_vuln = set()

    if args.should_setup:
        for pkgname in depends:
            print("---")
            checkout_or_update(pkgname)
            # do they have cargo_audit as a service? Could we consider adding it?
            (has_services, has_audit, has_vendor_update, lockfile) = does_have_cargo_audit(pkgname)
            lockfiles[pkgname] = lockfile

            if not has_vendor_update:
                print(f"😭  openSUSE:Factory/{pkgname} missing cargo_vendor service + update - the maintainer should be contacted to add this")
                need_services.add(f"{devel_projects[pkgname]}/{pkgname}")
            if not has_audit:
                print(f"⚠️   openSUSE:Factory/{pkgname} missing cargo_audit service - the maintainer should be contacted to add this")
                # print(f"✉️   https://build.opensuse.org/package/users/openSUSE:Factory/{pkgname}")
                # If not, we should contact the developers to add this. We can attempt to unpack
                # and run a scan still though.
                unpack_depends.append((pkgname, has_services))
                need_services.add(f"{devel_projects[pkgname]}/{pkgname}")
            else:
                # If they do, run services. We may not know what they need for this to work, so we
                # have to run the full stack, but at the least, the developer probably has this
                # working.
                auditable_depends.append(pkgname)

        for pkgname in auditable_depends:
            print("---")
            print(f"🛠  running services for {devel_projects[pkgname]}/{pkgname} ...")
            do_services(pkgname)

        for (pkgname, has_services) in unpack_depends:
            print("---")
            if has_services:
                print(f"🛠 running services for {devel_projects[pkgname]}/{pkgname} ...")
                do_services(pkgname)

    # Do the thang
    for pkgname in depends:
        print("---")
        print(f"🍿 unpacking and scanning {devel_projects[pkgname]}/{pkgname} ...")
        lockfile = lockfiles.get(pkgname, None)
        if not do_unpack_scan(pkgname, lockfile, args.rustsec_id):
            maybe_vuln.add(f"{devel_projects[pkgname]}/{pkgname}")

    need_services -= maybe_vuln
    print("--- complete")

    if len(maybe_vuln) > 0:
        if args.rustsec_id:
            print(f"- the following pkgs need SECURITY updates to address {args.rustsec_id}")
        else:
            print("- the following pkgs need SECURITY updates")
        for item in maybe_vuln:
            print(f"osc bco {item}")

    if len(need_services) > 0:
        print("- the following SHOULD have services updated")
        for item in need_services:
            print(f"osc bco {item}")



