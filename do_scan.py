#!/usr/bin/python3
import subprocess
import os
import xml.etree.ElementTree as ET
import tarfile


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
        root_node = ET.parse(service).getroot()
        for tag in root_node.findall('service'):
            if tag.attrib['name'] == 'cargo_audit':
                return (True, True)
        return (True, False)
    return (False, False)

def do_services(pkgname):
    try:
        out = subprocess.check_output(["osc", "service", "ra"], cwd=f"openSUSE:Factory/{pkgname}", encoding='UTF-8', stderr=subprocess.STDOUT)
        print(f"✅ -- services passed")
    except subprocess.CalledProcessError as e:
        print(f"🚨 -- services failed")
        print(e.stdout)

def do_unpack_scan(pkgname):
    # This will automatically do the unpack for use due to how cargo_audit as a service works :)
    try:
        out = subprocess.check_output(["osc", "service", "lr", "cargo_audit"], cwd=f"openSUSE:Factory/{pkgname}", encoding='UTF-8', stderr=subprocess.STDOUT)
        print(f"✅ -- cargo_audit passed")
    except subprocess.CalledProcessError as e:
        print(f"🚨 -- cargo_audit failed")
        print(e.stdout)

if __name__ == '__main__':
    depends = list_whatdepends()

    # For testing, we hardcode the list for dev.
    # depends = ['kanidm', 'librsvg', 'rust-cbindgen']

    # Check them out, or update if they exist.
    auditable_depends = []
    unpack_depends = []
    for pkgname in depends:
        print("---")
        checkout_or_update(pkgname)
        # do they have cargo_audit as a service? Could we consider adding it?
        (has_services, has_audit) = does_have_cargo_audit(pkgname)
        if not has_audit:
            print(f"⚠️   openSUSE:Factory/{pkgname} missing cargo_audit service - the maintainer should be contacted to add this")
            # print(f"✉️   https://build.opensuse.org/package/users/openSUSE:Factory/{pkgname}")
            # If not, we should contact the developers to add this. We can attempt to unpack
            # and run a scan still though.
            unpack_depends.append((pkgname, has_services))
        else:
            # If they do, run services. We may not know what they need for this to work, so we
            # have to run the full stack, but at the least, the developer probably has this
            # working.
            auditable_depends.append(pkgname)

    for pkgname in auditable_depends:
        print("---")
        print(f"🍿 running services for {pkgname} ...")
        do_services(pkgname)

    for (pkgname, has_services) in unpack_depends:
        print("---")
        if has_services:
            print(f"🍿 running services for {pkgname} ...")
            do_services(pkgname)
        print(f"🍿 unpacking and scanning {pkgname} ...")
        do_unpack_scan(pkgname)

    print("--- complete")

