# Keep security findings and coverage independent

The service headline shows confirmed findings when present, while a separate coverage flag remains visible for components with missing or failed checks. “No known findings” requires complete configured scanner and upstream advisory checks across every component; an unsupported advisory source remains a coverage gap, and ambiguous matches appear as possible findings outside confirmed severity counts. This conservative contract prevents a clean result from concealing missing evidence while still surfacing confirmed issues promptly.
