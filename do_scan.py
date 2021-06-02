#!/usr/bin/python3
import subprocess
import os
import xml.etree.ElementTree as ET


WHATDEPENDS = ["osc", "whatdependson", "openSUSE:Factory", "rust", "standard", "x86_64"]

CHECKOUT = ["osc", "co", "openSUSE:Factory"]
UPDATE = ["osc", "up", "openSUSE:Factory"]


EXCLUDE = set([
    'MozillaFirefox',
    'MozillaThunderbird',
    'rust',
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
    if os.path.exists('openSUSE:Factory') and os.path.exists(f'openSUSE:Factory/{pkgname}'):
        print(f"osc up openSUSE:Factory/{pkgname}")
        subprocess.check_call(["osc", "up", f"openSUSE:Factory/{pkgname}"])
    else:
        print(f"osc co openSUSE:Factory/{pkgname}")
        subprocess.check_call(["osc", "co", f"openSUSE:Factory/{pkgname}"])

def does_have_cargo_audit(pkgname):
    service = f"openSUSE:Factory/{pkgname}/_service"
    if os.path.exists(service):
        root_node = ET.parse(service).getroot()
        for tag in root_node.findall('service'):
            if tag.attrib['name'] == 'cargo_audit':
                return True
    return False

def do_services(pkgname):
    try:
        out = subprocess.check_output(["osc", "service", "ra"], cwd=f"openSUSE:Factory/{pkgname}", encoding='UTF-8', stderr=subprocess.STDOUT)
        print(f"✅ -- passed")
    except subprocess.CalledProcessError as e:
        print(f"🚨 -- services failed")
        print(e.stdout)

if __name__ == '__main__':
    depends = list_whatdepends()

    # For testing, we hardcode the list for dev.
    # depends = ['kanidm', 'librsvg', 'rust-cbindgen']

    # Check them out, or update if they exist.
    auditable_depends = []
    for pkgname in depends:
        print("---")
        checkout_or_update(pkgname)
        # do they have cargo_audit as a service?
        has_audit = does_have_cargo_audit(pkgname)
        if not has_audit:
            print(f"⚠️   https://build.opensuse.org/package/show/openSUSE:Factory/{pkgname} missing cargo_audit service")
            print(f"✉️   https://build.opensuse.org/package/users/openSUSE:Factory/{pkgname}")
            # subprocess.check_call(["osc", "maintainer", f"openSUSE:Factory/{pkgname}"])
        else:
            # If they do, run services. We may not know what they need for this to work, so we
            # have to run the full stack.
            auditable_depends.append(pkgname)

    for pkgname in auditable_depends:
        print("---")
        print(f"🍿 running services for {pkgname} ...")
        do_services(pkgname)

    print("--- complete")

