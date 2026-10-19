
import os
import json
import uuid
import math
import hashlib
from pathlib import Path
from datetime import datetime

import boto3
import streamlit as st
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CONFIGURATION
# ============================================================

APP_DIR = Path(__file__).resolve().parent
KEY_DIR = APP_DIR / "keys"
MANIFEST_DIR = APP_DIR / "manifests"

KEY_DIR.mkdir(exist_ok=True)
MANIFEST_DIR.mkdir(exist_ok=True)

BUCKET = os.getenv("SECURECLOUD_BUCKET", "").strip()
REGION = os.getenv("AWS_DEFAULT_REGION", "ap-southeast-2")

WEBSITE_URL = "https://de5m3mzls7nmp.cloudfront.net"

st.set_page_config(
    page_title="SecureCloud",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# STYLING
# ============================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

.stApp {
    background: #07111f;
    color: #e8f2ff;
    font-family: Inter, sans-serif;
}

.block-container {
    max-width: 1450px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

header[data-testid="stHeader"] {
    background: #07111f;
}

h1, h2, h3 {
    color: #f0f7ff;
}

.hero {
    padding: 30px;
    border-radius: 22px;
    border: 1px solid #234259;
    background: linear-gradient(120deg, #102940, #0b192a);
    margin-bottom: 24px;
}

.brand {
    color: #48e3d0;
    letter-spacing: 4px;
    font-weight: 800;
    font-size: 13px;
}

.hero-title {
    font-size: 38px;
    font-weight: 800;
    margin-top: 12px;
    margin-bottom: 8px;
}

.muted {
    color: #a2b6ca;
    line-height: 1.7;
}

.metric {
    background: #10243a;
    border: 1px solid #24445b;
    border-radius: 15px;
    padding: 18px;
    min-height: 115px;
}

.metric-label {
    font-size: 12px;
    color: #a2b6ca;
    margin-bottom: 12px;
}

.metric-value {
    font-size: 25px;
    font-weight: 800;
    color: #48e3d0;
    overflow-wrap: anywhere;
}

.metric-note {
    color: #a2b6ca;
    font-size: 11px;
    margin-top: 8px;
}

.panel {
    background: #0d1d30;
    border: 1px solid #213b51;
    border-radius: 16px;
    padding: 22px;
    margin: 12px 0;
}

.status {
    display: inline-block;
    color: #48e3d0;
    background: #10383a;
    border: 1px solid #23605e;
    padding: 6px 11px;
    border-radius: 30px;
    font-size: 11px;
    font-weight: 700;
}

.stButton button, .stDownloadButton button, .stLinkButton a {
    background: #35d7c6;
    color: #071522;
    border: 0;
    border-radius: 9px;
    font-weight: 800;
}

.stButton button:hover, .stDownloadButton button:hover {
    background: #7af1e4;
    color: #071522;
}

div[data-baseweb="tab-list"] {
    gap: 8px;
}

button[data-baseweb="tab"] {
    background: #0d1d30;
    border-radius: 9px;
    color: #b5c7d9;
    padding: 12px 16px;
}

button[data-baseweb="tab"][aria-selected="true"] {
    background: #123448;
    color: #48e3d0;
}

div[data-testid="stFileUploader"] {
    background: #0a1929;
    border: 1px dashed #32717b;
    border-radius: 12px;
    padding: 12px;
}

code {
    overflow-wrap: anywhere;
}

hr {
    border-color: #243b50;
}
</style>
""", unsafe_allow_html=True)


# ============================================================
# HELPERS
# ============================================================

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def log_activity(message: str):
    if "activity" not in st.session_state:
        st.session_state.activity = []

    st.session_state.activity.insert(
        0,
        f"{datetime.now().strftime('%H:%M:%S')} · {message}"
    )
    st.session_state.activity = st.session_state.activity[:30]


def metric_card(label, value, note):
    st.markdown(
        f"""
        <div class="metric">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def get_s3():
    if not BUCKET:
        raise RuntimeError(
            "S3 bucket is not configured. Set SECURECLOUD_BUCKET "
            "in the terminal before starting the application."
        )

    # Uses the standard AWS credential chain/profile.
    return boto3.client("s3", region_name=REGION)


def load_manifests():
    result = {}

    for path in sorted(MANIFEST_DIR.glob("*.json")):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
            result[manifest["file_id"]] = manifest
        except (OSError, ValueError, KeyError):
            continue

    return result


def safe_filename(name):
    # Avoid using user-provided directory paths.
    return Path(name).name.replace("/", "_").replace("\\", "_")


def check_bucket():
    try:
        s3 = get_s3()
        s3.head_bucket(Bucket=BUCKET)
        return True, "Private S3 bucket is reachable."
    except RuntimeError as exc:
        return False, str(exc)
    except (BotoCoreError, ClientError) as exc:
        return False, f"AWS connection failed: {exc}"


# ============================================================
# HEADER
# ============================================================

if "activity" not in st.session_state:
    st.session_state.activity = []

st.markdown("""
<div class="hero">
    <div class="brand">SECURECLOUD · CLOUD SECURITY</div>
    <div class="hero-title">Your files. Your keys. Your control.</div>
    <p class="muted">
        Secure file transfer, encrypted block storage and integrity verification.
    </p>
    <span class="status">AES-256-GCM · SHA-256</span>
</div>
""", unsafe_allow_html=True)


# ============================================================
# TABS
# ============================================================

dashboard, transfer, verification, architecture = st.tabs([
    "☁️ Cloud Dashboard",
    "🔒 Secure File Transfer",
    "✓ Integrity Verification",
    "⌘ Architecture & Info",
])


# ============================================================
# 01 - DASHBOARD
# ============================================================

with dashboard:
    st.subheader("Cloud Dashboard")
    st.markdown(
        '<p class="muted">Your project status and recent file activity.</p>',
        unsafe_allow_html=True,
    )

    manifests = load_manifests()
    bucket_ok, bucket_message = check_bucket()

    total_files = len(manifests)
    total_blocks = sum(m.get("block_count", 0) for m in manifests.values())

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        metric_card(
            "PRIVATE S3 STORAGE",
            "Connected" if bucket_ok else "Not connected",
            "Live bucket check",
        )

    with c2:
        metric_card("FILES PROCESSED", total_files, "Local manifests")

    with c3:
        metric_card("ENCRYPTED BLOCKS", total_blocks, "Recorded block count")

    with c4:
        metric_card("ENCRYPTION", "AES-256-GCM", "Authenticated encryption")

    if bucket_ok:
        st.success(bucket_message)
    else:
        st.warning(bucket_message)

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown("### Deployment information")

    st.write("**Application:** SecureCloud Streamlit application")
    st.write("**AWS region:**", REGION)
    st.write("**Website CDN:** Amazon CloudFront")
    st.write("**Website protocol:** HTTPS")
    st.write("**File storage:** Separate private S3 bucket")

    st.markdown("**Existing documentation website**")
    st.code(WEBSITE_URL, language=None)
    st.link_button("Open documentation website ↗", WEBSITE_URL)

    st.caption(
        "This is the existing static website URL. It is not the address "
        "of this local Streamlit application."
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("### Recent activity")

    if st.session_state.activity:
        for event in st.session_state.activity:
            st.write("•", event)
    else:
        st.info("No operations recorded in this session.")


# ============================================================
# 02 - SECURE FILE TRANSFER
# ============================================================

with transfer:
    st.subheader("Secure File Transfer")
    st.markdown(
        '<p class="muted">Split, encrypt and upload file blocks to private S3.</p>',
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        "Choose a file to protect",
        key="securecloud_upload",
    )

    block_size_mb = st.selectbox(
        "Block size",
        [1, 2, 4, 8],
        index=0,
        format_func=lambda x: f"{x} MB",
    )

    if uploaded is not None:
        file_data = uploaded.getvalue()
        file_hash = sha256(file_data)
        block_size = block_size_mb * 1024 * 1024
        block_count = max(1, math.ceil(len(file_data) / block_size))

        a, b, c = st.columns(3)

        with a:
            metric_card("SELECTED FILE", safe_filename(uploaded.name), "Filename")

        with b:
            metric_card("FILE SIZE", f"{len(file_data):,} B", "Original bytes")

        with c:
            metric_card("BLOCKS", block_count, f"{block_size_mb} MB each")

        st.markdown("**Original SHA-256**")
        st.code(file_hash)

        if st.button("Encrypt and upload to private S3", type="primary"):
            try:
                s3 = get_s3()

                # Test access before starting the upload.
                s3.head_bucket(Bucket=BUCKET)

                file_id = uuid.uuid4().hex
                key = AESGCM.generate_key(bit_length=256)
                aes = AESGCM(key)

                # Key is stored locally, never uploaded to S3.
                key_path = KEY_DIR / f"{file_id}.key"
                key_path.write_bytes(key)

                objects = []
                progress = st.progress(0.0)
                status = st.empty()

                for index in range(block_count):
                    start = index * block_size
                    plaintext_block = file_data[start:start + block_size]

                    # A unique random nonce is generated for every block.
                    nonce = os.urandom(12)
                    aad = f"{file_id}:{index}".encode("utf-8")
                    ciphertext = aes.encrypt(
                        nonce, plaintext_block, aad
                    )

                    # Store nonce together with ciphertext.
                    encrypted_payload = nonce + ciphertext
                    object_key = (
                        f"securecloud/{file_id}/block-{index:05d}.bin"
                    )

                    s3.put_object(
                        Bucket=BUCKET,
                        Key=object_key,
                        Body=encrypted_payload,
                        ContentType="application/octet-stream",
                        ServerSideEncryption="AES256",
                    )

                    objects.append(object_key)
                    progress.progress((index + 1) / block_count)
                    status.write(
                        f"Uploaded encrypted block {index + 1} of {block_count}"
                    )

                manifest = {
                    "file_id": file_id,
                    "filename": safe_filename(uploaded.name),
                    "original_size": len(file_data),
                    "original_sha256": file_hash,
                    "block_size": block_size,
                    "block_count": block_count,
                    "blocks": objects,
                    "created_at": datetime.now().isoformat(),
                    "algorithm": "AES-256-GCM",
                    "region": REGION,
                }

                manifest_path = MANIFEST_DIR / f"{file_id}.json"
                manifest_path.write_text(
                    json.dumps(manifest, indent=2),
                    encoding="utf-8",
                )

                # Upload metadata only. The encryption key is excluded.
                s3.put_object(
                    Bucket=BUCKET,
                    Key=f"securecloud/{file_id}/manifest.json",
                    Body=json.dumps(manifest, indent=2).encode("utf-8"),
                    ContentType="application/json",
                    ServerSideEncryption="AES256",
                )

                log_activity(
                    f"Encrypted and uploaded {safe_filename(uploaded.name)} "
                    f"({block_count} block(s))"
                )

                st.success("Encrypted blocks uploaded successfully.")
                st.write("**File ID:**", file_id)
                st.write("**Encrypted blocks:**", block_count)
                st.write("**Key location:**", str(key_path))
                st.warning(
                    "Back up your local key and manifest securely. "
                    "If the key is lost, the file cannot be decrypted. "
                    "Never upload the key to S3."
                )

            except (RuntimeError, BotoCoreError, ClientError, OSError) as exc:
                st.error(f"Upload failed: {exc}")

    st.divider()
    st.markdown("### Download and reconstruct")

    manifests = load_manifests()

    if not manifests:
        st.info("Upload a file first. Its manifest will be saved locally.")
    else:
        choices = {
            f"{m['filename']} · {fid[:8]}": fid
            for fid, m in manifests.items()
        }

        selected_label = st.selectbox(
            "Choose an uploaded file",
            list(choices.keys()),
        )

        if st.button("Download, decrypt and verify"):
            try:
                s3 = get_s3()
                file_id = choices[selected_label]
                manifest = manifests[file_id]

                key_path = KEY_DIR / f"{file_id}.key"

                if not key_path.exists():
                    raise RuntimeError(
                        "Local encryption key is missing. "
                        "Decryption cannot proceed without the original key."
                    )

                key = key_path.read_bytes()
                if len(key) != 32:
                    raise RuntimeError("The local AES-256 key is invalid.")

                aes = AESGCM(key)
                reconstructed = bytearray()
                block_total = len(manifest["blocks"])
                progress = st.progress(0.0)

                for index, object_key in enumerate(manifest["blocks"]):
                    response = s3.get_object(
                        Bucket=BUCKET,
                        Key=object_key,
                    )
                    payload = response["Body"].read()

                    if len(payload) < 12 + 16:
                        raise RuntimeError(
                            f"Encrypted block {index} is incomplete."
                        )

                    nonce = payload[:12]
                    ciphertext = payload[12:]
                    aad = f"{file_id}:{index}".encode("utf-8")

                    # AES-GCM raises an exception if authentication fails.
                    plaintext = aes.decrypt(nonce, ciphertext, aad)
                    reconstructed.extend(plaintext)

                    progress.progress((index + 1) / block_total)

                recovered = bytes(reconstructed)
                original_hash = manifest["original_sha256"]
                reconstructed_hash = sha256(recovered)
                verified = (
                    reconstructed_hash == original_hash
                    and len(recovered) == manifest["original_size"]
                )

                st.session_state["verification_result"] = {
                    "filename": manifest["filename"],
                    "original_hash": original_hash,
                    "reconstructed_hash": reconstructed_hash,
                    "verified": verified,
                    "data": recovered,
                    "size": len(recovered),
                }

                log_activity(
                    f"Downloaded and reconstructed {manifest['filename']}"
                )

                if verified:
                    st.success(
                        "Integrity verified: reconstructed file matches original."
                    )
                else:
                    st.error(
                        "Integrity verification failed. Do not trust this file."
                    )

            except (RuntimeError, BotoCoreError, ClientError, OSError) as exc:
                st.error(f"Download failed: {exc}")
            except Exception as exc:
                st.error(
                    "Decryption failed. The key, encrypted data, or "
                    f"authentication check may be invalid. Details: {exc}"
                )

    result = st.session_state.get("verification_result")

    if result:
        st.markdown("### Reconstructed file")

        st.write("**Filename:**", result["filename"])
        st.write("**Size:**", f"{result['size']:,} bytes")

        st.download_button(
            "Download reconstructed original",
            data=result["data"],
            file_name=result["filename"],
            mime="application/octet-stream",
        )


# ============================================================
# 03 - INTEGRITY VERIFICATION
# ============================================================

with verification:
    st.subheader("Integrity Verification")
    st.markdown(
        '<p class="muted">Verify that the downloaded file matches the original.</p>',
        unsafe_allow_html=True,
    )

    result = st.session_state.get("verification_result")

    if result:
        st.markdown('<div class="panel">', unsafe_allow_html=True)

        st.markdown("**Original SHA-256**")
        st.code(result["original_hash"])

        st.markdown("**Reconstructed SHA-256**")
        st.code(result["reconstructed_hash"])

        if result["verified"]:
            st.success("PASS · The hashes and file sizes match.")
        else:
            st.error("FAIL · The reconstructed file does not match.")

        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info(
            "Verification results appear after you download and reconstruct "
            "a file in Secure File Transfer."
        )

    st.markdown("### Transfer activity log")

    if st.session_state.activity:
        for event in st.session_state.activity:
            st.write("•", event)
    else:
        st.info("No activity recorded yet.")


# ============================================================
# 04 - ARCHITECTURE AND PROJECT INFORMATION
# ============================================================

with architecture:
    st.subheader("Architecture & Project Information")

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown("### System architecture")

    st.markdown("""
    ```text
    User / Browser
         |
         | HTTPS
         v
    CloudFront CDN
         |
         | Origin Access Control (OAC)
         v
    Private S3 Website Bucket

    Local SecureCloud Application
         |
         v
    Split file into blocks
         |
         v
    AES-256-GCM encryption
         |
         +----> Encryption key stays local
         |
         v
    Private S3 File Storage Bucket
         |
         v
    Download encrypted blocks
         |
         v
    Local decryption and reconstruction
         |
         v
    SHA-256 integrity comparison
    ```
    """)

    st.markdown("</div>", unsafe_allow_html=True)

    left, right = st.columns(2)

    with left:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Amazon S3")
        st.write(
            "Stores the encrypted blocks. Keep the bucket private and "
            "grant access only to authorized AWS identities."
        )
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### CloudFront and HTTPS")
        st.write(
            "CloudFront distributes the static documentation website. "
            "HTTPS protects data in transit to that website."
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### AES-256-GCM")
        st.write(
            "Authenticated encryption protects each block and detects "
            "tampering. Each block uses a fresh random nonce."
        )
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### SHA-256")
        st.write(
            "Computes a fingerprint of the original and reconstructed "
            "files to check that they match."
        )
        st.markdown("</div>", unsafe_allow_html=True)

    st.warning(
        "The Streamlit app runs separately from the static CloudFront website. "
        "The CloudFront URL shown in the dashboard refers to your existing "
        "documentation website, not this running Python app."
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")
st.markdown(
    """
    <p style="text-align:center;color:#8098ae;font-size:12px;">
        SECURECLOUD · CLOUD COMPUTING MINI PROJECT<br>
        Private storage · Encrypted blocks · Integrity verification
    </p>
    """,
    unsafe_allow_html=True,
)
