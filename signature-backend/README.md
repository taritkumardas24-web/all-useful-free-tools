# PDF Signature Verification API

This service is a backend scaffold for the Digital Signature Validator in the static website.

## Safety and trust configuration

The API intentionally refuses to issue a green Verified result until **both** of these Render environment variables are configured:

- `CCA_ROOT_CERT_PEM`: PEM-encoded current CCA India root certificate.
- `CCA_ROOT_SHA256_HEX`: SHA-256 fingerprint independently confirmed out-of-band with CCA. Do not copy a fingerprint from an untrusted mirror or rely only on downloading the certificate over HTTPS.

Use the current root certificate published by the official CCA site. CCA's root-certificate page instructs users to obtain out-of-band verification of root certificate fingerprints. Keep the root certificate and fingerprint matched. Do not configure expired roots as current trust anchors.

The validator uses pyHanko with the configured CCA trust anchor and hard-fail revocation mode. A missing/invalid root, failed signature, failed trust path, or unavailable required revocation evidence must never produce a green result. The API does not verify whether Aadhaar/PAN/caste details match an issuing authority's database.

## Deploy on Render

1. Sign in to Render and create a new Blueprint using this repository.
2. Render reads `signature-backend/render.yaml` and builds the Docker service.
3. Set `CCA_ROOT_CERT_PEM` and `CCA_ROOT_SHA256_HEX` only after obtaining the official CCA root and its out-of-band fingerprint confirmation.
4. Wait for the service to become healthy at `/health`.
5. Copy the service base URL and configure `window.SIGNATURE_API_BASE` in the website before enabling public use. Do not put private keys or secrets in the frontend.

The free Render instance may sleep when idle. Production use may require a paid always-on instance and additional security review.

## API

- `GET /health`: service and trust configuration status.
- `POST /api/verify`: multipart PDF upload, maximum 25 MB.

Uploaded PDFs are processed in memory and are not written to persistent storage by this application. Network certificate/revocation retrieval may contact URLs embedded in certificate metadata; deploy with network egress controls and resource limits before accepting public traffic.

## Current limitations

- This initial version returns a verification report; it does not yet generate a flattened/print-ready display copy.
- Multiple PDF upload is not yet implemented.
- CCA root fingerprint pinning must be completed before green verification can be enabled.
- It is not an official government service and does not query Aadhaar/PAN/caste certificate databases.
