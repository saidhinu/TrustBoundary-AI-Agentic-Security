"""Create a narrated slideshow of REAL v1.6 UI screenshots.

It is expressly a screenshot walkthrough, not a live browser action recording.
Participant should record their own real-time UI walkthrough for final judging.
"""
from pathlib import Path
import subprocess, tempfile, wave
from PIL import Image, ImageOps, ImageDraw, ImageFont
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'submission'/'TrustBoundary_Demo_Walkthrough_Narrated.mp4'
imgs=ROOT/'submission'/'screenshots'
scenes=[
 ('01_attack_lab.png','ATTACK LAB','Inspect suspicious content in synthetic email and tool messages.',19),
 ('02_before_after.png','BEFORE / AFTER','The insecure baseline is a SCRIPT, not a real compromised language model.',23),
 ('03_evaluation.png','EVALUATION','The old template benchmark is narrow: 45 detected out of 45 attacks.',20),
 ('04_audit.png','TRACES','Audit shows inspections, policy decisions, and blocked mock tool operations.',19),
 ('06_architecture.png','INDEPENDENT AUTHORIZATION','External documents supply facts, but cannot grant tool permissions.',23),
 ('07_settings.png','OPTIONAL OPENAI','Each user can bring a private API key; offline fallback works without one.',21),
 ('05_impact.png','LIMITATIONS','A separate 40-case challenge detects only 7/20 attacks; 50 benign emails have 2 false alerts.',22),
]
assert sum(d for *_,d in scenes)==147
script=[
 'TrustBoundary AI version one point six is an offline-first synthetic agent security prototype. This video is a narrated walkthrough of the actual application screenshots.',
 'The attack lab compares a vulnerable scripted reference and the protected workflow. Neither side performs a real payment, and the reference is not a compromised real language model.',
 'The original templated holdout detected forty five out of forty five attacks. Those results are not evidence of open-world generalization.',
 'The trace view records classification and tool authorization decisions. The authorization gate is implemented independently of the risk classifier.',
 'The main security invariant is provenance before permission: an untrusted email, PDF, or website cannot upgrade the identity or authority of the user.',
 'The settings page accepts an optional personally supplied OpenAI key. Offline inspection still works without a key. Live hosted model performance has not been verified.',
 'The separate forty-case challenge still detects only seven of twenty unfamiliar attacks, and the additional fifty benign business emails produce two false alerts. Claim only provisional F three D one. Further independent red teaming is required.',
]
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    fnt='/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
    f=ImageFont.truetype(fnt,31)
    v=ImageFont.truetype(fnt,22)
    ff=td/'list.txt'
    strings=[]
    for i,(name,title,sub,duration) in enumerate(scenes):
        im=Image.open(imgs/name).convert('RGB')
        im=ImageOps.fit(im,(1280,720),method=Image.Resampling.LANCZOS,centering=(0.5,0.12))
        bar=Image.new('RGBA',(1280,88),(5,15,30,232))
        im_rgba=im.convert('RGBA');im_rgba.alpha_composite(bar,(0,0))
        draw=ImageDraw.Draw(im_rgba)
        draw.text((24,8),f'TRUSTBOUNDARY AI v1.6.0  /  {title}',fill=(69,220,170),font=f)
        draw.text((24,51),sub,fill=(235,242,249),font=v)
        draw.rectangle((0,695,1280,720),fill=(3,18,32,250))
        draw.text((18,696),'SCREENSHOT WALKTHROUGH · SYNTHETIC SANDBOX · F3-D1 PROVISIONAL',font=ImageFont.truetype(fnt,16),fill=(235,242,248))
        path=td/f'frame_{i:02d}.png';im_rgba.convert('RGB').save(path)
        strings.extend([f"file '{path}'",f'duration {duration}'])
    strings.append(f"file '{path}'")
    ff.write_text('\n'.join(strings)+'\n')
    silent=td/'silent.mp4'
    subprocess.run(['ffmpeg','-hide_banner','-loglevel','error','-y','-f','concat','-safe','0','-i',str(ff),
      '-fps_mode','vfr','-vf','fps=10,format=yuv420p','-c:v','libx264','-preset','veryfast','-crf','26','-t','147',str(silent)],check=True)
    sounds=[];rate=22050;start=0
    for i,(scene,speech) in enumerate(zip(scenes,script)):
        p=td/f'{i:02d}.wav'
        subprocess.run(['espeak','-v','en','-s','153','-w',str(p),speech],check=True,stdout=subprocess.DEVNULL)
        with wave.open(str(p),'rb') as wav:
            data=np.frombuffer(wav.readframes(wav.getnframes()),dtype=np.int16).copy()
            assert wav.getframerate()==rate
            sounds.append((start*rate,data))
        start+=scene[-1]
    outaudio=np.zeros(147*rate,dtype=np.int32)
    for st,part in sounds:
        en=min(len(outaudio),st+len(part))
        outaudio[st:en]+=part[:en-st].astype(np.int32)
    audiopath=td/'voice.wav'
    with wave.open(str(audiopath),'wb') as wav:
        wav.setnchannels(1);wav.setsampwidth(2);wav.setframerate(rate)
        wav.writeframes(np.clip(outaudio,-32768,32767).astype(np.int16).tobytes())
    subprocess.run(['ffmpeg','-hide_banner','-loglevel','error','-y','-i',str(silent),'-i',str(audiopath),
        '-map','0:v:0','-map','1:a:0','-c:v','copy','-c:a','aac','-b:a','128k','-movflags','+faststart',
        '-shortest',str(OUT)],check=True)
print(f'Created screenshot-only walkthrough: {OUT}, {OUT.stat().st_size:,} bytes')
