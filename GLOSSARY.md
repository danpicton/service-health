# Service Health

Terms used to describe update and security information for the home-server services.

## Language

**Service**:
A logical home-server application shown as one item to the user. A service may contain several components.

**Component**:
A separately versioned or deployed part of a service whose update and security state can differ from the rest of the service.

**Coverage gap**:
A missing or incomplete security check that prevents a complete account of known findings for a component or service.

**Finding**:
A reported security issue affecting a deployed component, with its scanner or upstream advisory source retained.

**Possible finding**:
A reported security issue whose applicability to a deployed component cannot be established reliably. It is shown separately from confirmed finding counts.

**No known findings**:
A security result with no reported findings and complete checks across every component at the stated check time. It does not assert that no vulnerabilities exist.

**Stale result**:
A previously successful check result retained after a newer scheduled check failed or its freshness limit passed.

**Image rebuild**:
A change to the image digest for the deployed platform while its image tag remains the same.

**Major migration**:
An available stable release that advances the application's major version and may require deliberate upgrade work.
