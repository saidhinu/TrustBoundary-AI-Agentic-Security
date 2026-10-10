"""Rebuild v1.4 narrated demo from Git-tracked binary chunks.
This is deterministic packaging, not a generated or modified video.
"""
import hashlib
from pathlib import Path
root=Path(__file__).resolve().parents[1]
parts=sorted((root/'submission'/'media_chunks').glob('*.part'))
if len(parts)!=7:
    raise SystemExit(f'Expected 7 video chunks, found {len(parts)}')
data=b''.join(p.read_bytes() for p in parts)
expected='ab1ea88ed1cc0a060fec4defb8a91323bf7832344a11addb7ef2694a0f01f954'
actual=hashlib.sha256(data).hexdigest()
if actual!=expected:
    raise SystemExit(f'Video SHA256 mismatch: expected {expected}, got {actual}')
out=root/'submission'/'TrustBoundary_Demo_Walkthrough_Narrated.mp4'
out.write_bytes(data)
print(f'Verified narrated demo: {out} ({len(data)} bytes, SHA256 {actual})')
