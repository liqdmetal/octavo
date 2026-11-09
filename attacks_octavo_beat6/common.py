"""Read-only import of LIVE N2 (Octavo beat-6-fix attack); independent NumPy batching, validated against live round_enc."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib
EXPECTED_SHA='922a29d89be68b29a2be08873ff5a99a7cf264afebe1ece0387aa0f4fe56fe10'
HERE=Path(__file__).resolve().parent
REPO=HERE.parent
LIVE=REPO/'sneak_n2.py'
_actual=hashlib.sha256(LIVE.read_bytes()).hexdigest()
if _actual!=EXPECTED_SHA:
 raise SystemExit('attacks_octavo_beat6 is a historical report pinned to '+EXPECTED_SHA[:12]+
  '; this tree has '+_actual[:12]+'. It cannot replay against another revision;'
  ' see fix_beat0rot_verification/ for the current one.')
sys.path.insert(0,str(REPO))
import sneak_n2 as N
import numpy as np
import json, random, re, hmac, time, datetime, math
from zoneinfo import ZoneInfo
LIVE_SHA=hashlib.sha256(Path(N.__file__).read_bytes()).hexdigest()
assert Path(N.__file__).resolve()==LIVE and LIVE_SHA==EXPECTED_SHA,(N.__file__,LIVE_SHA)
def verify_live():
 cur=hashlib.sha256(LIVE.read_bytes()).hexdigest()
 assert cur==EXPECTED_SHA,('STOP: wrong live target',cur);return cur
SEED=N.load_seed(str(REPO/'sneak1024-seed.txt'))
HB=bytes.fromhex(re.search(r'blob \(195 bytes.*?: ([0-9a-f]+)',(REPO/'hello-world.txt').read_text()).group(1))
_,PICKUP,NONCE,CT,TAG=N.split_blob(HB)
_hb=lambda f:bytes.fromhex(re.search(r'blob \(195 bytes.*?: ([0-9a-f]+)',Path(f).read_text()).group(1))
PREV_BLOB=_hb('/tmp/sneak_n2_pre_beat6/hello-world.txt')   # beat-7 era, pickup ee95ddb2...
PREV7_BLOB=_hb('/tmp/sneak_n2_pre_beat7/hello-world.txt')  # pre-beat-7, pickup 76908595...
SCH=N.Schedule(SEED,NONCE)
DEMO_NONCE=bytes.fromhex((REPO/'demo-nonce.txt').read_text().strip())
def now():return datetime.datetime.now(ZoneInfo('America/New_York')).strftime('%Y-%m-%d %I:%M:%S %p %Z (America/New_York)')
def save(name,obj):
 text=json.dumps(obj,indent=2,default=str)+'\n';(HERE/(name+'_results.json')).write_text(text);(HERE/(name+'_output.txt')).write_text(now()+'\n'+text);print(name,'saved',flush=True)
def flat(g):return N.grid_to_bytes(g)
GF=np.array([list(x) for x in N._GF_MUL],dtype=np.int64)
M2=N.MIX2_MATRIX
def rotl(x,r):return ((x<<r)|(x>>(8-r)))&255
def mix2v(u,v):return GF[M2[0][0],u]^GF[M2[0][1],v],GF[M2[1][0],u]^GF[M2[1][1],v]
def latin(u,v,S,S2):return S[u^v],S2[u^GF[2,v]]
def bars(x,S,S2):
 x=x.reshape(-1,16,8).copy()
 for name,_,(i,j),M in N.BARS:
  u=x[:,:,i].copy();v=x[:,:,j].copy()
  if name=='B0 start':x[:,:,i],x[:,:,j]=latin(u,v,S,S2)
  else:x[:,:,i]=GF[M[0][0],u]^GF[M[0][1],v];x[:,:,j]=GF[M[1][0],u]^GF[M[1][1],v]
 return x.reshape(-1,128)
def trips(x):
 x=x.reshape(-1,16,8).copy()
 for _,(i,j,k),M in N.TRIPLETS:
  u=x[:,:,i].copy();v=x[:,:,j].copy();w=x[:,:,k].copy()
  for pos,(a,b,c) in zip((i,j,k),M):x[:,:,pos]=(a*u+b*v+c*w)&255
 return x.reshape(-1,128)
OLD_STROKES=((0,1,2),(2,3,4),(4,5,6),(6,7,0),(1,2,3),(3,4,5),(5,6,0))   # previous (beat-7-fix) layout, comparison only
OLD7_STROKES=((0,1,2),(2,3,4),(4,5,6),(6,7,0),(1,2,3),(3,4,5),(5,6,7))  # pre-beat-7-fix layout
def bow(x,strokes=None):
 x=x.reshape(-1,16,8).copy()
 for i,j,p in (N.BOW_STROKES if strokes is None else strokes):
  pp=x[:,:,p];r1=N.BOW_ROT_BASE+(pp%N.BOW_ROT_MOD);r2=N.BOW_ROT_BASE+((pp>>N.BOW_R2_SHIFT)%N.BOW_ROT_MOD)
  u=(x[:,:,i]+rotl(x[:,:,j],r1))&255;x[:,:,i]=u;x[:,:,j]=x[:,:,j]^rotl(u,r2)
 return x.reshape(-1,128)
def rehair(x,S,S2):
 x=x.reshape(-1,16,8).copy()
 for t in (1,3,5,7):
  u=x[:,:,t-1].copy();v=x[:,:,t].copy();x[:,:,t-1],x[:,:,t]=latin(u,v,S,S2)
 return x.reshape(-1,128)
def cross(x):
 x=x.reshape(-1,16,8).copy()
 for layer in N.CROSS_LAYERS:
  for i,j in layer:
   u=x[:,i,:].copy();v=x[:,j,:].copy();x[:,i,:],x[:,j,:]=mix2v(u,v)
 return x.reshape(-1,128)
class Batch:
 def __init__(self,sch):
  self.sch=sch;self.perms=[];self.staff=[];self.shell=[];self.S=[];self.S2=[];self.rk=[]
  for r,k in enumerate(sch.rounds):
   self.perms.append(np.array(N.weave([list(range(i*8,i*8+8)) for i in range(16)],k['SH'],k['SV'])).reshape(128))
   layers=[]
   for m in N.LAYERS:
    pairs=[(f*8+s[i],f*8+s[i|m]) for f,s in enumerate(k['sigma']) for i in range(8) if not i&m]
    layers.append(tuple(np.array(t) for t in zip(*pairs)))
   self.staff.append(layers)
   a=np.arange(64);fo=np.array(k['bridge'])//8+8;to=np.array(k['bridge'])%8;b=fo*8+to
   self.shell.append((b,a) if r%2 else (a,b))
   self.S.append(np.array(k['S'],dtype=np.int64));self.S2.append(np.array(k['S2'],dtype=np.int64))
   self.rk.append(np.frombuffer(flat(k['rk']),dtype=np.uint8).astype(np.int64))
  self.white=np.frombuffer(flat(sch.white),dtype=np.uint8).astype(np.int64)
 def linear(self,x,r):
  x=np.asarray(x,dtype=np.int64)[:,self.perms[r]].copy()
  for a,b in self.staff[r]+[self.shell[r]]:
   u=x[:,a].copy();v=x[:,b].copy();x[:,a],x[:,b]=mix2v(u,v)
  return x
 def half(self,x,r):
  S,S2=self.S[r],self.S2[r]
  return cross(rehair(bow(trips(bars(x,S,S2))),S,S2))
 def round(self,x,r,key=True):
  x=np.asarray(x,dtype=np.int64)
  x=self.S[r][x^self.rk[r] if key else x]
  x=self.half(self.linear(x,r),r);x=self.S2[r][x]
  return self.half(x,r)
 def enc(self,x,rounds=16,white=False,start=0):
  for r in range(start,start+rounds):x=self.round(x,r)
  return x^self.white if white else x
 def validate(self,count=6,seed=713):
  rng=np.random.default_rng(seed);x=rng.integers(0,256,(count,128));y=x.copy()
  for r in range(16):
   x=self.round(x,r)
   for i in range(count):y[i]=np.frombuffer(flat(N.round_enc(N.bytes_to_grid(bytes(y[i].astype(np.uint8))),self.sch.rounds[r],r)),dtype=np.uint8)
   assert np.array_equal(x,y),(r,'batch mismatch')
  raw=rng.integers(0,256,(1,128))
  assert bytes(self.enc(raw,16,True)[0].astype(np.uint8))==flat(N.encrypt_grid(N.bytes_to_grid(bytes(raw[0].astype(np.uint8))),self.sch))
  return count*16
def tobytes(row):return bytes(np.asarray(row).astype(np.uint8))

def bow_staff(x,strokes=None):
 """x: (n,8) int64 staffs -> bow output (n,8)."""
 x=np.asarray(x,dtype=np.int64).copy()
 for i,j,p in (N.BOW_STROKES if strokes is None else strokes):
  pp=x[:,p];r1=N.BOW_ROT_BASE+(pp%N.BOW_ROT_MOD);r2=N.BOW_ROT_BASE+((pp>>N.BOW_R2_SHIFT)%N.BOW_ROT_MOD)
  u=(x[:,i]+rotl(x[:,j],r1))&255;x[:,i]=u;x[:,j]=x[:,j]^rotl(u,r2)
 return x
def rehair_staff(x,S,S2):
 x=np.asarray(x,dtype=np.int64).copy()
 for t in (1,3,5,7):
  u=x[:,t-1].copy();v=x[:,t].copy();x[:,t-1],x[:,t]=latin(u,v,S,S2)
 return x
