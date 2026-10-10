from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
import hashlib,json
root=Path(__file__).resolve().parent.parent
out=root.parent/'TrustBoundary_AI_Submission_Package.zip'
exclude_dirs={'__pycache__','.pytest_cache','.git','.venv'}
exclude_names={'audit.sqlite3','server.log','video_build.log','video_pid','slide1.png','slide7.png','demo_preview.jpg','TrustBoundary_Demo_Walkthrough.webm','TrustBoundary_Demo_Walkthrough.mp4'}
files=[p for p in root.rglob('*') if p.is_file() and not any(part in exclude_dirs for part in p.relative_to(root).parts) and p.name not in exclude_names and p.suffix not in {'.pyc','.db','.sqlite3'}]
with ZipFile(out,'w',ZIP_DEFLATED,compresslevel=7) as z:
 for f in sorted(files):z.write(f,arcname='TrustBoundary_AI/'+str(f.relative_to(root)))
check={'package':str(out),'files':len(files),'bytes':out.stat().st_size,'sha256':hashlib.sha256(out.read_bytes()).hexdigest(), 'contains':[str(p.relative_to(root)) for p in files if p.suffix in {'.mp4','.pptx','.pdf','.json'}]}
print(json.dumps(check,indent=2))
