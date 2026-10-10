"""Create synthetic narrated version of the real app screen recording."""
import subprocess,wave,tempfile
from pathlib import Path
import numpy as np
root=Path(__file__).resolve().parent.parent
video=root/'submission'/'TrustBoundary_Demo_Walkthrough.mp4'
out=root/'submission'/'TrustBoundary_Demo_Walkthrough_Narrated.mp4'
scenes=[
(0,'Introducing TrustBoundary AI version one point two, a provisional F three D one prototype. An agentic security control plane protecting enterprise workflows from instructions hidden inside untrusted content.'),
(9,'Our synthetic payments assistant receives a merchant settlement request together with a forged system-level instruction in the email.'),
(21,'Now we execute identical content using a deliberately vulnerable scripted reference and the protected TrustBoundary workflow.'),
(30,'The reference simulation attempts a refund. The protected agent blocks that tool action through independent permissions and still drafts the legitimate ticket.'),
(44,'Next, a benign merchant request should pass inspection and retain the ordinary settlement workflow.'),
(55,'Encoded payloads are inspected with source provenance and redacted evidence. No real secrets are used.'),
(67,'The E G O evaluation cockpit displays measured synthetic test results, not fabricated demonstration numbers.'),
(82,'We examine precision, recall, false positives, task completion, and per-category coverage. These templated tests do not establish production performance.'),
(94,'Every significant inspection, tool decision, and outcome generates a structured event in the local audit timeline.'),
(105,'The F three D one evidence map links attack categories to synthetic test cases. We do not claim D two reliability.'),
(115,'The architecture separates untrusted documents from user authority. The policy engine alone determines which tools may run.'),
(125,'This calculator illustrates hypothetical economic value using transparent assumptions, not measured customer financial savings.'),
(136,'TrustBoundary version one point two. Provenance before permission. A working synthetic prototype requiring further independent security validation before real-world deployment.')
]
with tempfile.TemporaryDirectory() as td:
 sounds=[];rate=None
 for i,(start,sentence) in enumerate(scenes):
  path=Path(td)/f's_{i:02d}.wav'
  subprocess.run(['espeak','-v','en','-s','157','-w',str(path),sentence],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  with wave.open(str(path),'rb') as f:
   assert f.getnchannels()==1 and f.getsampwidth()==2
   rate=f.getframerate() if rate is None else rate
   raw=np.frombuffer(f.readframes(f.getnframes()),dtype=np.int16).copy()
  sounds.append((int(start*rate),raw))
 n=int(152.5*rate)
 sound=np.zeros(n,dtype=np.int32)
 for start,data in sounds:
  end=min(n,start+len(data))
  sound[start:end]+=data[:end-start].astype(np.int32)
 sound=np.clip(sound*.90,-32768,32767).astype(np.int16)
 wav=Path(td)/'narration.wav'
 with wave.open(str(wav),'wb') as f:
  f.setnchannels(1);f.setsampwidth(2);f.setframerate(rate);f.writeframes(sound.tobytes())
 subprocess.run(['ffmpeg','-hide_banner','-loglevel','error','-y','-i',str(video),'-i',str(wav),'-map','0:v:0','-map','1:a:0','-c:v','copy','-c:a','aac','-b:a','128k','-ar','44100','-shortest','-movflags','+faststart',str(out)],check=True)
print('Narrated demo video',out,out.stat().st_size)
