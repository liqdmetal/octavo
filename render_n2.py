#!/usr/bin/env python3
# Octavo (sneak staff-core N2): render dual octahedra + 16x8 hex grid for the CURRENT live design.
# Reads the recorded hello-world sample (pickup/nonce/ct/tag); does NOT overwrite hello-world.txt,
# demo-nonce.txt, sneak_n2.py, tests, snapshots, or attacks_*.
# Seed split: INNER seed (first 128 hex digits) on a wine shell hugging the inner octahedron;
# OUTER seed (last 128) on the amber shell around the outer octahedron.
import sys, math, os, re
WORK=os.environ.get("OCTAVO_WORK","/workspace")  # parent of the sneak_n2 folder
sys.dont_write_bytecode = True
sys.path.insert(0,os.path.join(WORK,'sneak_n2'))
from PIL import Image, ImageDraw, ImageFont
import sneak_n2 as N
KEY=N.load_seed()
HW=open(os.path.join(WORK,'sneak_n2','hello-world.txt')).read()
def _hx(label):
    m=re.search(rf'{label}.*?: ([0-9a-f]+)', HW, re.I|re.S)
    if not m: raise SystemExit(f'missing {label} in hello-world.txt')
    return bytes.fromhex(m.group(1))
pickup=_hx('pickup'); nonce=_hx('nonce'); ct=_hx('ciphertext'); tag=_hx('tag')
assert len(pickup)==N.PICKUP_LEN and len(nonce)==N.NONCE_LEN and len(ct)==N.BLOCK_LEN and len(tag)==N.TAG_LEN
assert nonce==N.siv_nonce(b'hello world', pickup, KEY)
blob=N.VERSION+pickup+nonce+ct+tag
rec=N.decrypt(blob,KEY); assert rec==b'hello world'
final=N.bytes_to_grid(ct); sch=N.Schedule(KEY,nonce)
# round-0 shell bridges, aggregated to face pairs (inner f <-> outer 8+g), weight = number of bridged cells
from collections import Counter
BR=Counter((c//8, 8+sch.rounds[0]['bridge'][c]//8) for c in range(64))
PAIRS=sorted(BR)
SEEDHEX=KEY.hex()
hx=lambda r:'| '+' | '.join(' '.join(f'{n:02X}' for n in r[2*m:2*m+2]) for m in range(4))+' |'
names=[f'inner {k+1}' for k in range(8)]+[f'outer o{k+1}' for k in range(8)]
print('decrypt OK:',rec); print('pickup',pickup.hex()); print('nonce',nonce.hex()); print('tag',tag.hex())
for k in range(16): print(names[k],hx(final[k]))
# ---------------- draw ----------------
W,H=5200,3720; paper=(244,239,228); ink=(28,25,20); purple=(58,33,88); muted=(106,97,84); red=(150,40,40); teal=(30,90,95)
Fd='/usr/share/fonts/truetype/dejavu/'
titf=ImageFont.truetype(Fd+'DejaVuSerif.ttf',72); subf=ImageFont.truetype(Fd+'DejaVuSans.ttf',34)
hexf=ImageFont.truetype(Fd+'DejaVuSansMono-Bold.ttf',76); smallf=ImageFont.truetype(Fd+'DejaVuSans-Bold.ttf',30)
numf=ImageFont.truetype(Fd+'DejaVuSerif-Bold.ttf',40); headf=ImageFont.truetype(Fd+'DejaVuSerif-Bold.ttf',50)
yaw=math.radians(20); pitch=math.radians(20); cam=7.5; f=3900; cx,cy=1500,H/2+10
RI,RO,RS=0.85,1.9,2.6     # inner, outer, seed shell
amber=(150,98,12); amber_l=(206,168,96)
def xf(p):
    x,y,z=p; x,y=x*math.cos(yaw)-y*math.sin(yaw),x*math.sin(yaw)+y*math.cos(yaw)
    return x,y*math.sin(pitch)+z*math.cos(pitch),y*math.cos(pitch)-z*math.sin(pitch)
def P(p):
    x,u,dp=xf(p); zz=cam+dp; return (cx+f*x/zz,cy-f*u/zz)
UP=[(1,-1),(1,1),(-1,1),(-1,-1)]
faces=[(a,b,1) for a,b in UP]+[(-a,-b,-1) for a,b in UP]
def facing(n,R):
    c=tuple(R*v/3 for v in n); p=xf(c); m=xf(n)
    return m[0]*p[0]+m[1]*p[1]+m[2]*(p[2]+cam)<0
def verts(n,R): return (0,0,n[2]*R),(n[0]*R,0,0),(0,n[1]*R,0)
cent=lambda n,R:tuple(R*v/3 for v in n)
img=Image.new('RGBA',(W,H),paper+(255,))
EDG=[((0,0,1),(1,0,0)),((0,0,1),(-1,0,0)),((0,0,1),(0,1,0)),((0,0,1),(0,-1,0)),((0,0,-1),(1,0,0)),((0,0,-1),(-1,0,0)),((0,0,-1),(0,1,0)),((0,0,-1),(0,-1,0)),((1,0,0),(0,1,0)),((0,1,0),(-1,0,0)),((-1,0,0),(0,-1,0)),((0,-1,0),(1,0,0))]
def shell(R,alpha_f,alpha_b,col):
    global img
    lay=Image.new('RGBA',(W,H),(0,0,0,0)); d=ImageDraw.Draw(lay)
    for fr in (False,True):
        for k in range(8):
            if facing(faces[k],R)!=fr: continue
            sh=[232,214,200,222,206,190,178,196][k]
            d.polygon([P(v) for v in verts(faces[k],R)],fill=(sh+col[0],sh-6+col[1],sh-18+col[2],alpha_f if fr else alpha_b))
    img=Image.alpha_composite(img,lay)
def edges(R,w,colf,colb):
    d=ImageDraw.Draw(img)
    for a,b in EDG:
        A=tuple(R*v for v in a); B=tuple(R*v for v in b)
        fr=any(facing(fc,R) for fc in faces if all(sum(x*y for x,y in zip(fc,v))>0.5 for v in (a,b)))
        p,q=P(A),P(B)
        if fr: d.line([p,q],fill=colf,width=w)
        else:
            for j in range(0,30,2):
                d.line([(p[0]+(q[0]-p[0])*j/30,p[1]+(q[1]-p[1])*j/30),(p[0]+(q[0]-p[0])*(j+1)/30,p[1]+(q[1]-p[1])*(j+1)/30)],fill=colb,width=max(2,w-3))
# ---- seed split: inner seed = first 128 hex digits (bits 0-511) <-> inner octahedron,
#                  outer seed = last 128 hex digits (bits 512-1023) <-> outer octahedron
RIS=1.32                                   # inner seed shell: hugs the inner octahedron (RI=0.85), inside the outer (RO=1.9)
INNER_SEED, OUTER_SEED = SEEDHEX[:128], SEEDHEX[128:]
assert len(INNER_SEED)==len(OUTER_SEED)==128 and INNER_SEED+OUTER_SEED==SEEDHEX
wine=(122,22,48); wine_l=(196,140,150)
VX={'T':(0,0,1),'B':(0,0,-1),'+X':(1,0,0),'-X':(-1,0,0),'+Y':(0,1,0),'-Y':(0,-1,0)}
EULER=['T','+X','-Y','B','-X','+Y','B','+X','+Y','T','-X','-Y','T']        # Euler circuit: 12 edges, each once
SEDGES=[(EULER[i],EULER[i+1]) for i in range(12)]
assert len({frozenset(e) for e in SEDGES})==12
def thread(R,digits):
    """lay `digits` as one unbroken thread along the Euler circuit; per-edge counts proportional to projected length."""
    Ls=[math.dist(P(tuple(R*v for v in VX[a_])),P(tuple(R*v for v in VX[b_]))) for a_,b_ in SEDGES]
    q=[len(digits)*l/sum(Ls) for l in Ls]; cnt=[int(x) for x in q]
    for i_ in sorted(range(12),key=lambda i_:-(q[i_]-int(q[i_])))[:len(digits)-sum(cnt)]: cnt[i_]+=1
    assert sum(cnt)==len(digits)
    pos=[]; edge_of=[]
    for i,(a_,b_) in enumerate(SEDGES):
        A=tuple(R*v for v in VX[a_]); B=tuple(R*v for v in VX[b_])
        for k in range(cnt[i]):
            t=0.07+0.86*(k+0.5)/cnt[i]; pos.append(tuple(A[c]+(B[c]-A[c])*t for c in range(3))); edge_of.append(i)
    front=[any(facing(fc,R) for fc in faces if all(sum(x*y for x,y in zip(fc,VX[v]))>0.5 for v in e)) for e in SEDGES]
    return dict(R=R,digits=digits,cnt=cnt,pos=pos,edge_of=edge_of,front=front,spacing=sum(Ls)*0.86/len(digits))
TIN=thread(RIS,INNER_SEED); TOUT=thread(RS,OUTER_SEED)
print('inner seed digits per edge:',TIN['cnt'],'~px',round(TIN['spacing']),'| outer seed digits per edge:',TOUT['cnt'],'~px',round(TOUT['spacing']))
def draw_thread(T,front,col,col_l,ff,fb,lw):
    dd=ImageDraw.Draw(img); R=T['R']
    for i,(a_,b_) in enumerate(SEDGES):
        if T['front'][i]!=front: continue
        p,q=P(tuple(R*v for v in VX[a_])),P(tuple(R*v for v in VX[b_]))
        if front: dd.line([p,q],fill=col,width=lw)
        else:
            for j in range(0,40,2): dd.line([(p[0]+(q[0]-p[0])*j/40,p[1]+(q[1]-p[1])*j/40),(p[0]+(q[0]-p[0])*(j+1)/40,p[1]+(q[1]-p[1])*(j+1)/40)],fill=col_l,width=2)
    for j,(pt3,ch) in enumerate(zip(T['pos'],T['digits'])):
        if T['front'][T['edge_of'][j]]!=front: continue
        pt=P(pt3); fo=ff if front else fb; ch=ch.upper(); bb=dd.textbbox((0,0),ch,font=fo); x0,y0=pt[0]-(bb[0]+bb[2])/2,pt[1]-(bb[1]+bb[3])/2
        if front: dd.text((x0,y0),ch,font=fo,fill=col,stroke_width=4,stroke_fill=paper)
        else: dd.text((x0,y0),ch,font=fo,fill=col_l)
def skin(R,rgb,af,ab):
    global img
    lay=Image.new('RGBA',(W,H),(0,0,0,0)); ld=ImageDraw.Draw(lay)
    for k in range(8): ld.polygon([P(v) for v in verts(faces[k],R)],fill=rgb+(af if facing(faces[k],R) else ab,))
    img=Image.alpha_composite(img,lay)
# chunking: each seed half = 8 chunks of 16 hex digits (64 bits); chunk -> one face of its OWN octahedron.
# assignment = the chunk<->face matching (8! options) with the shortest total 3D link length, so links stay readable.
import itertools
def chunk_mid(T,c): return T['pos'][16*c+8]
def match(T,R):
    best=None
    for perm in itertools.permutations(range(8)):
        s=sum(math.dist(chunk_mid(T,c),cent(faces[perm[c]],R)) for c in range(8))
        if best is None or s<best[0]: best=(s,perm)
    return best[1]
MIN=match(TIN,RI); MOUT=match(TOUT,RO)
print('inner chunk->inner face:',[f'c{c}->{MIN[c]+1}' for c in range(8)]); print('outer chunk->outer face:',[f'c{c}->o{MOUT[c]+1}' for c in range(8)])
fontsI=(ImageFont.truetype(Fd+'DejaVuSansMono-Bold.ttf',30),ImageFont.truetype(Fd+'DejaVuSansMono.ttf',22))
fontsO=(ImageFont.truetype(Fd+'DejaVuSansMono-Bold.ttf',40),ImageFont.truetype(Fd+'DejaVuSansMono.ttf',30))
def chunk_bands(T,col,alpha):
    """translucent band under each 16-digit chunk (alternating strength) so the 8 chunks read as units"""
    global img
    lay=Image.new('RGBA',(W,H),(0,0,0,0)); ld=ImageDraw.Draw(lay)
    for c in range(8):
        pts=[P(T['pos'][16*c+k]) for k in range(16)]
        ld.line(pts,fill=col+(alpha if c%2==0 else alpha//2,),width=26,joint='curve')
    img=Image.alpha_composite(img,lay)
def seed_links(T,M,R,col,width,alpha,base=0):
    global img
    lay=Image.new('RGBA',(W,H),(0,0,0,0)); ld=ImageDraw.Draw(lay)
    for c in range(8):
        p1=P(chunk_mid(T,c)); p2=P(cent(faces[M[c]],R)); c0_=P((0,0,0))
        ctrl=((p1[0]+p2[0])/2*0.85+c0_[0]*0.15,(p1[1]+p2[1])/2*0.85+c0_[1]*0.15)
        pts=[((1-t)**2*p1[0]+2*(1-t)*t*ctrl[0]+t*t*p2[0],(1-t)**2*p1[1]+2*(1-t)*t*ctrl[1]+t*t*p2[1]) for t in [i/30 for i in range(31)]]
        ld.line(pts,fill=col+(alpha,),width=width,joint='curve')
        for (x_,y_),r_ in ((p1,13),(p2,11)): ld.ellipse([x_-r_,y_-r_,x_+r_,y_+r_],fill=col+(255,))
        ux,uy=p1[0]-c0_[0],p1[1]-c0_[1]; nn=math.hypot(ux,uy) or 1; lab=f'{base+16*c}–{base+16*c+15}'; tb=ld.textbbox((0,0),lab,font=smallf)
        lx,ly=p1[0]+ux/nn*48-(tb[2])/2,p1[1]+uy/nn*48-(tb[3])/2       # label pushed radially outward from the chunk dot
        ld.text((lx,ly),lab,font=smallf,fill=col+(240,),stroke_width=3,stroke_fill=paper+(230,))
    img=Image.alpha_composite(img,lay)

# open 8-beat staffs on the 3D faces: a straight OPEN line of 8 dots per face (two measures of 4/4 split by a bar);
# beat 1 and beat 8 are ends (end ticks), not joined -- the staffs are unlooped.
def staff_line(k,R,col,rr,front,L=8):
    global img
    n=faces[k]; C=cent(n,R); V0=verts(n,R)[0]
    u=[V0[i]-C[i] for i in range(3)]; lu=math.sqrt(sum(x*x for x in u)); u=[x/lu for x in u]
    nn=[x/math.sqrt(3) for x in n]; w=[nn[1]*u[2]-nn[2]*u[1],nn[2]*u[0]-nn[0]*u[2],nn[0]*u[1]-nn[1]*u[0]]
    pt=lambda s_,t_: P(tuple(C[i]+s_*w[i]+t_*u[i] for i in range(3)))
    half=rr*1.25; xs=[-half+2*half*(b+0.5)/L for b in range(L)]   # 4 measures of 2 beats between 5 bar marks
    lay=Image.new('RGBA',(W,H),(0,0,0,0)); ld=ImageDraw.Draw(lay); a_=210 if front else 70
    if front: ld.polygon([pt(-half*1.08,-rr*0.30),pt(half*1.08,-rr*0.30),pt(half*1.08,rr*0.30),pt(-half*1.08,rr*0.30)],fill=paper+(190,),outline=col+(140,))
    ld.line([pt(-half,0),pt(half,0)],fill=col+(a_ if front else a_//2,),width=3 if front else 2)
    if front:
        BC=[(176,40,40),(30,110,60),(28,25,20),(40,70,170),(150,70,0)]
        for i_,e_ in enumerate((-half,-half/2,0,half/2,half)):                                  # five bar marks B0..B4
            hh=rr*(0.24 if i_ in (0,2,4) else 0.17)
            ld.line([pt(e_,-hh),pt(e_,hh)],fill=BC[i_]+(235,),width=5 if i_ in (0,2,4) else 4)
        for b in range(L):
            x_,y_=pt(xs[b],0); r_=10 if b==0 else 7
            ld.ellipse([x_-r_,y_-r_,x_+r_,y_+r_],fill=col+(255,))
    img=Image.alpha_composite(img,lay)
# 1. OUTER SEED shell (amber, last 128 digits): skin + far edges
skin(RS,(214,170,80),20,30)
chunk_bands(TOUT,(214,160,60),70)
draw_thread(TOUT,False,amber,amber_l,*fontsO,4)
# 2. outer octahedron
shell(RO,50,70,(0,8,10))
edges(RO,5,teal,(110,150,150))
for k in range(8): staff_line(k,RO,teal,0.38,facing(faces[k],RO))      # outer open 8-beat staffs
# 3. outer seed -> outer faces o1..o8 (gold links; drawn before the inner octahedron so it overlays them)
seed_links(TOUT,MOUT,RO,(196,128,0),8,215,base=128)     # labels use global seed digit indices 128-255
# 4. INNER SEED shell (wine, first 128 digits): skin + far edges
skin(RIS,(200,120,130),16,24)
chunk_bands(TIN,(170,60,80),60)
draw_thread(TIN,False,wine,wine_l,*fontsI,3)
# 5. inner octahedron
shell(RI,110,190,(0,0,0))
edges(RI,5,ink,(120,112,100))
for k in range(8): staff_line(k,RI,purple,0.21,facing(faces[k],RI))    # inner open 8-beat staffs
d=ImageDraw.Draw(img)
fc=[P(cent(faces[k],RI)) for k in range(8)]+[P(cent(faces[k],RO)) for k in range(8)]
c0=P((0,0,0))
# 6. round-0 inner<->outer ciphertext bridges, demoted to thin grey so the seed links dominate
mesh=Image.new('RGBA',(W,H),(0,0,0,0)); md=ImageDraw.Draw(mesh)
for (A_,B_) in PAIRS:
    p1,p2=fc[A_],fc[B_]
    ctrl=(c0[0]*0.6+(p1[0]+p2[0])/2*0.4, c0[1]*0.6+(p1[1]+p2[1])/2*0.4)
    pts=[((1-t)**2*p1[0]+2*(1-t)*t*ctrl[0]+t*t*p2[0],(1-t)**2*p1[1]+2*(1-t)*t*ctrl[1]+t*t*p2[1]) for t in [i/24 for i in range(25)]]
    md.line(pts,fill=(110,110,118,45+12*BR[(A_,B_)]),width=1+BR[(A_,B_)]//2)
for q in fc[:8]: md.line([c0,q],fill=wine+(170,),width=4)          # core spokes: inner faces ONLY
img=Image.alpha_composite(img,mesh)
# 7. inner seed -> inner faces 1..8 (wine links)
seed_links(TIN,MIN,RI,wine,7,225)
for r_,a_ in ((120,60),(95,120),(75,255)):
    lay=Image.new('RGBA',(W,H),(0,0,0,0)); ImageDraw.Draw(lay).ellipse([c0[0]-r_,c0[1]-r_,c0[0]+r_,c0[1]+r_],fill=(110,30,40,a_)); img=Image.alpha_composite(img,lay)
d=ImageDraw.Draw(img)
for t_,fo,dy in (('inner',smallf,-38),('seed',numf,-2),(INNER_SEED[:8]+'…',smallf,38)):
    bb=d.textbbox((0,0),t_,font=fo); d.text((c0[0]-(bb[0]+bb[2])/2,c0[1]+dy-(bb[1]+bb[3])/2),t_,font=fo,fill=(250,240,230))
# 8. inner seed near edges (under the badges so face numbers stay readable)
draw_thread(TIN,True,wine,wine_l,*fontsI,3)
d=ImageDraw.Draw(img)
for k in range(8): q=fc[k]; d.ellipse([q[0]-8,q[1]-8,q[0]+8,q[1]+8],fill=wine)
for k in range(8,16): q=fc[k]; d.ellipse([q[0]-8,q[1]-8,q[0]+8,q[1]+8],fill=(196,128,0))
def badge(pos,txt,fr,outer):
    x,y=pos; bb=d.textbbox((0,0),txt,font=numf); w=max(70,bb[2]+30)
    oc=teal if outer else ink
    d.rounded_rectangle([x-w/2,y-34,x+w/2,y+34],30,fill=paper if fr else (228,224,214),outline=oc if fr else (150,150,150),width=3)
    d.text((x-(bb[0]+bb[2])/2,y-(bb[1]+bb[3])/2),txt,font=numf,fill=oc if fr else muted)
for k in range(8):
    q=P(cent(faces[k],RI)); badge((q[0],q[1]-58),str(k+1),facing(faces[k],RI),False)
for k in range(8):
    q=P(cent(faces[k],RO)); badge((q[0],q[1]+58),f'o{k+1}',facing(faces[k],RO),True)
# 9. outer seed near edges on top, labels and start markers
draw_thread(TOUT,True,amber,amber_l,*fontsO,4)
d=ImageDraw.Draw(img)
st=P(tuple(RS*v for v in VX['T'])); lab_='OUTER SEED · last 128 hex digits (bits 512–1023) · 8 chunks of 16 → outer faces o1–o8'
bb=d.textbbox((0,0),lab_,font=smallf); d.text((st[0]-bb[2]/2,st[1]-70),lab_,font=smallf,fill=amber)
d.ellipse([st[0]-11,st[1]-11,st[0]+11,st[1]+11],fill=amber); d.text((st[0]+22,st[1]-8),'start / end',font=smallf,fill=amber)
si=P(tuple(RIS*v for v in VX['T']))
d.ellipse([si[0]-9,si[1]-9,si[0]+9,si[1]+9],fill=wine)
lab_='INNER SEED · first 128 hex digits (bits 0–511) → inner faces 1–8'
bb=d.textbbox((0,0),lab_,font=smallf); d.text((si[0]-bb[2]-24,si[1]-20),lab_,font=smallf,fill=wine,stroke_width=3,stroke_fill=paper)
# cards
# 16x8 hex table: four measures of 2/4; bar lines B0/B1/B2/B3/B4 plus mid-measure field mixes M2/M3
tx0=3010; ty0=400; rowh=152; labw=320; colw=172; mg=56; gap=60
hf=ImageFont.truetype(Fd+'DejaVuSansMono-Bold.ttf',78); barf=ImageFont.truetype(Fd+'DejaVuSans-Bold.ttf',28); legf=ImageFont.truetype(Fd+'DejaVuSansMono-Bold.ttf',24)
tinyf=ImageFont.truetype(Fd+'DejaVuSans-Bold.ttf',22)
BARCOL=[(176,40,40),(30,110,60),(28,25,20),(40,70,170),(150,70,0)]          # B0..B4
MCOL=(95,55,130)                                                            # M2/M3
def bx(b): return tx0+labw+b*colw+(b//2)*mg                                   # left edge of beat b
def barx(i): return bx(2*i)-mg/2 if 0<i<4 else (bx(0)-mg/4 if i==0 else bx(7)+colw+mg/4)
def midx(b0,b1): return (bx(b0)+colw+bx(b1))/2                                # between two beats
tw_=bx(7)+colw+mg/2+30-tx0
gy1=ty0+16*rowh+gap
d.rounded_rectangle([tx0-40,ty0-150,tx0+tw_+20,gy1+390],24,fill=(250,247,240),outline=ink,width=3)
for m in range(4):
    xm=(bx(2*m)+bx(2*m+1)+colw)/2; t_=f'm{m+1} · 2/4'; bb=d.textbbox((0,0),t_,font=smallf); d.text((xm-bb[2]/2,ty0-142),t_,font=smallf,fill=muted)
for b in range(8):
    x=bx(b)+colw/2; t_=f'b{b+1}'; bb=d.textbbox((0,0),t_,font=smallf); d.text((x-bb[2]/2,ty0-100),t_,font=smallf,fill=muted)
# named mix marks above the staff (B0..B4 on bar lines; M2/M3 mid-measure)
for i,lab in enumerate(('B0','B1','B2','B3','B4')):
    bb=d.textbbox((0,0),lab,font=barf); d.text((barx(i)-bb[2]/2,ty0-60),lab,font=barf,fill=BARCOL[i])
for lab,x in (('M2',midx(2,3)),('M3',midx(4,5))):
    bb=d.textbbox((0,0),lab,font=tinyf); d.text((x-bb[2]/2,ty0-58),lab,font=tinyf,fill=MCOL)
def draw_bar(i,x,y0,y1):
    c=BARCOL[i]
    if i==0:   d.line([(x,y0),(x,y1)],fill=c,width=8); d.line([(x+12,y0),(x+12,y1)],fill=c,width=3)          # start: thick+thin
    elif i==1: [d.line([(x,yy),(x,min(yy+16,y1))],fill=c,width=5) for yy in range(int(y0),int(y1),26)]     # dashed
    elif i==2: d.line([(x-5,y0),(x-5,y1)],fill=c,width=4); d.line([(x+5,y0),(x+5,y1)],fill=c,width=4)      # center: double
    elif i==3: [d.ellipse([x-4,yy-4,x+4,yy+4],fill=c) for yy in range(int(y0)+4,int(y1),16)]               # dotted
    else:      d.line([(x-12,y0),(x-12,y1)],fill=c,width=3); d.line([(x,y0),(x,y1)],fill=c,width=8)        # end: thin+thick
def draw_mid(x,y0,y1):
    [d.line([(x,yy),(x,min(yy+10,y1))],fill=MCOL+(180,),width=3) for yy in range(int(y0),int(y1),18)]
for k in range(16):
    y=ty0+k*rowh+(gap if k>=8 else 0)
    outer=k>=8; oc=teal if outer else purple
    if k%2==0: d.rectangle([tx0-20,y,tx0+tw_,y+rowh],fill=(240,235,222))
    lab_=('outer o' if outer else 'inner ')+str(k%8+1)
    bb=d.textbbox((0,0),lab_,font=numf); d.text((tx0,y+(rowh-bb[3])/2),lab_,font=numf,fill=oc)
    for b in range(8):
        x=bx(b)+colw/2
        g='·' if final[k][b] is None else f'{final[k][b]:02X}'; bb=d.textbbox((0,0),g,font=hf)
        d.rounded_rectangle([x-colw/2+5,y+8,x+colw/2-5,y+rowh-8],12,fill=(233,242,241),outline=(80,110+final[k][b]//3,155),width=4)
        d.text((x-(bb[0]+bb[2])/2,y+rowh/2-(bb[1]+bb[3])/2),g,font=hf,fill=oc)
    for i in range(5): draw_bar(i,barx(i),y+18,y+rowh-18)
    draw_mid(midx(2,3),y+28,y+rowh-28); draw_mid(midx(4,5),y+28,y+rowh-28)
    # clef mark at the start of the staff (seed-only staff clef, bound into the tag)
    cx_=barx(0)-34; cy_=y+rowh/2
    d.arc([cx_-16,cy_-30,cx_+16,cy_+30],60,300,fill=red,width=6); d.line([(cx_-22,cy_-40),(cx_-22,cy_+40)],fill=red,width=5)
    # encore flourish after the end line B4 (bars+triplets+bow+rehair+cross repeated after late S2)
    ex_=barx(4)+16; ey_=y+rowh/2
    d.arc([ex_,ey_-22,ex_+22,ey_+22],270,90,fill=(150,70,0),width=5); d.ellipse([ex_+4,ey_-30,ex_+12,ey_-22],fill=(150,70,0)); d.ellipse([ex_+4,ey_+22,ex_+12,ey_+30],fill=(150,70,0))
d.line([(tx0-20,ty0+8*rowh+gap/2),(tx0+tw_,ty0+8*rowh+gap/2)],fill=ink,width=4)
# compact legend: seven named pair mixes + bow / triplets / restack / cross
leg_pairs=[]
for name, boundary, pair, M in N.BARS:
    kind='latin S/S2' if name.startswith('B0') else 'GF(2^8)'
    leg_pairs.append(f"{name}: beats ({pair[0]+1},{pair[1]+1}) → ({M[0][0]}u+{M[0][1]}v, {M[1][0]}u+{M[1][1]}v)  [{kind}]")
head_lines=[
    'seven named pair mixes (latin B0 + field B1/M2/B2/M3/B3/B4) · six overlapping triplets · bow-pressure · latin odd restack',
    'cross-staff · red clef bound into the tag · encore after late S2 · open staffs (no loop)',
]
for j,hl in enumerate(head_lines):
    d.text((tx0,gy1+4+j*30),hl,font=barf,fill=ink)
for i,t_ in enumerate(leg_pairs):
    col_=i%2; row_=i//2
    colr = BARCOL[0] if i==0 else (MCOL if 'M2' in t_ or 'M3' in t_ else BARCOL[min(1+(i>1)+(i>3)+(i>5),4)])
    # map colors: B0 red, B1 green, M2 purple, B2 black, M3 purple, B3 blue, B4 orange
    cmap=[BARCOL[0],BARCOL[1],MCOL,BARCOL[2],MCOL,BARCOL[3],BARCOL[4]]
    d.text((tx0+col_*900,gy1+68+row_*34),t_,font=legf,fill=cmap[i])
bow_lines=[
    "bow-pressure strokes (i,j,p): (0,1,2)(2,3,4)(4,5,0)(6,7,0)(1,2,3)(3,4,5)(5,6,0)  ·  beat-0 readers rotl 0/3/5",
    "odd restack latin pairs (0,1)(2,3)(4,5)(6,7)  ·  triplets T0–T5  ·  cross-staff: opposite → radial → adjacent → bridge",
]
for j,bow_line in enumerate(bow_lines):
    d.text((tx0,gy1+68+4*34+8+j*32),bow_line,font=legf,fill=teal)
# titles
t='Octavo (sneak staff-core N2)  ·  8-bit cells  ·  pickup · clef & encore  ·  key signature'
bb=d.textbbox((0,0),t,font=titf); d.text(((W-bb[2])/2,36),t,font=titf,fill=ink)
t='keyed SM4-affine S-boxes · latin B0 + field bar pairs · six triplets · bow-pressure (beat-0 readers rotl 0/3/5) · latin odd restack · cross-staff mix · open 8-beat staffs · SIV nonce from clef‖pickup‖msg · HMAC tag over clef‖key_sig‖SN2‖pickup‖nonce‖ct · grid IS ciphertext'
bb=d.textbbox((0,0),t,font=subf); d.text(((W-bb[2])/2,128),t,font=subf,fill=muted)
warn='NOT for real secrets — use AES-GCM-SIV, age, or libsodium'
bb=d.textbbox((0,0),warn,font=headf); d.text(((W-bb[2])/2,178),warn,font=headf,fill=red)
# footer
footf=ImageFont.truetype(Fd+'DejaVuSans.ttf',30)
lines=[
    f"pickup {pickup.hex()}   ·   nonce {nonce.hex()}",
    f"tag {tag.hex()}   ·   blob = SN2 ‖ pickup ‖ nonce ‖ ct ‖ tag   ·   \"hello world\" sample",
    "seed split: INNER seed (wine, first 128 digits) ↔ inner octahedron 1–8 · OUTER seed (amber, last 128 digits) ↔ outer octahedron o1–o8 · thin grey: round-0 inner↔outer ciphertext bridges",
    "each round: ⊕key → keyed S-box → weave → staff butterfly → shell bridges → bars+triplets → bow → odd restack → cross-staff → late S2 → encore (bars+triplets+bow+restack+cross) · code-closure key signature",
]
for i,line in enumerate(lines):
    bb=d.textbbox((0,0),line,font=footf); d.text(((W-bb[2])/2,H-340+i*48),line,font=footf,fill=red if i<2 else muted)
seedcap=ImageFont.truetype(Fd+'DejaVuSansMono-Bold.ttf',26)
parts=[('inner ',wine),(INNER_SEED.upper(),wine),(' | ',ink),(OUTER_SEED.upper(),amber),(' outer',amber)]
tw=sum(d.textlength(t_,font=seedcap) for t_,_ in parts); x_=(W-tw)/2; y_=H-340+4*48+4
for t_,c_ in parts: d.text((x_,y_),t_,font=seedcap,fill=c_); x_+=d.textlength(t_,font=seedcap)
print('seed shell extents:',[tuple(round(c) for c in P(tuple(RS*v for v in VX[k]))) for k in VX])
img.convert('RGB').save(os.path.join(WORK,'sneak-staff-n2.png')); img.convert('RGB').save(os.path.join(WORK,'sneak_n2','sneak-staff-n2.png')); print('wrote',img.size)
