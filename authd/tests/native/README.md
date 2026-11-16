# General authentication in a development guest

These fixtures are for a fresh, disposable Peios guest. They create local
accounts with a public test password and replace machine authentication policy.
Never run them on an installed machine or a guest with data to preserve.

Build raw targets in their component worktrees:

```sh
pekit build -j 2 authd lpsd lps authn_probe libpeios
```

Build matching `peinit2` and `svctl` in peinit's worktree. All consumers must
use the same version-2 auth-core revision. No package or image build is needed.

Boot an existing console image with its kernel and initramfs and add
`init=/bin/bash` to the kernel command line. Mount a read-only 9p development
share with `trans=virtio,version=9p2000.L,ro,policy=synth-ephemeral`. Copy the
raw programs to `/lcl/sbin/{authd,lpsd}` and
`/lcl/bin/{peinit2,svctl,lps,authn-probe}`; copy matching libpeios.so.0 to
`/lcl/lib`. Before starting any services, run:

```sh
export LD_LIBRARY_PATH=/lcl/lib
exec /lcl/bin/peinit2
```

Use the explicit development path. The composed `/bin/peinit2` can still name
the image's original binary after a copy into `/lcl`; that would keep PID 1 on
the old protocol. After boot, run `setup.sh` from this directory in the guest:

```sh
PEIOS_DISPOSABLE_AUTH_TEST=yes bash /mnt/dev/authd-authenticate/authd/tests/native/setup.sh
```

The allowed probe runs as a distinct virtual service account with Authenticate
but no Logon capability or token-creation privilege. The script exercises real
ServiceAttest provisioning and KACS object-ACE checks. It checks password
success, complete group disclosure, a case-equivalent claim grant, explicit
absence, unrequested fields, bad/disabled/no-credential failures, denied
disclosure before prompting, and lack of Logon authority. Separate probes check
missing capability, caller logon-type policy, SYSTEM operation authorization,
malformed policy, the PID-1 attestation gate, and ordinary Logon finalization.

Identity probes exercise lookup, principal enumeration and enumeration of a
group's members. A selected-claim service grant cannot read the complete CLAIMS
field. A blanket grant permits that field, but a Department-specific deny
withholds it, including for SYSTEM. Names, numbers and memberships remain
available. A policy change takes effect on the next request over an existing
connection. Malformed policy withholds claims without disabling identity lookup.

The SYSTEM no-local-state probe enumerates kernel sessions and checks the
principal's private registry root and home. Authentication must create none of
them and must leave its caller's token unchanged. Logon must subsequently
return a real token with the reported authentication ID and prepare a home.

Success markers begin with `NATIVE`. Keep their output and the exact source
revisions in the work's Acta record. Stop the guest and remove copied runtime
files, extracted boot files and component build outputs when finished.
