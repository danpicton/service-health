# Schedule Trivy scans in the service-health collector

The initial security collector schedules Trivy scans for pullable deployed image digests and accepts externally supplied reports for images it cannot pull. This keeps the first release independent of a cluster-wide Trivy Operator deployment and allows local fixture testing. Images without a usable scan remain explicit coverage gaps; moving to Operator reports later would change the runtime integration and report ownership.
