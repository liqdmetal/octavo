"""Reproducible empirical comparison, not a security bound. Never writes snapshots."""
import sys, os, importlib.util, random, json
WORK=os.environ.get("OCTAVO_WORK","/workspace")  # parent of the sneak_n2 folder
sys.dont_write_bytecode=True
import sneak_n2 as NEW
spec=importlib.util.spec_from_file_location('precolor2','/tmp/sneak_n2_8bit_precolor2/sneak_n2.py')
OLD=importlib.util.module_from_spec(spec); spec.loader.exec_module(OLD)
seed=NEW.load_seed()
def measure(N):
    rr=random.Random(5); union=[[set() for _ in range(128)] for _ in range(3)]
    for p in range(128):
        for _ in range(4):
            sch=N.Schedule(seed,bytes(rr.randrange(256) for _ in range(16)))
            g=[[rr.randrange(256) for _ in range(8)] for _ in range(16)]
            h=[row[:] for row in g]; h[p//8][p%8]^=rr.randrange(1,256)
            for r in range(3):
                g=N.round_enc(g,sch.rounds[r],r); h=N.round_enc(h,sch.rounds[r],r)
                union[r][p]|={8*f+t for f in range(16) for t in range(8) if g[f][t]!=h[f][t]}
    mins=[min(map(len,u)) for u in union]
    rr=random.Random(20261108); hs=[[],[]]
    for _ in range(300):
        sch=N.Schedule(seed,bytes(rr.randrange(256) for _ in range(16)))
        x=bytes(rr.randrange(256) for _ in range(128)); y=bytearray(x); bit=rr.randrange(1024); y[bit//8]^=1<<(bit%8)
        g=N.bytes_to_grid(x); h=N.bytes_to_grid(y)
        for r in range(2):
            g=N.round_enc(g,sch.rounds[r],r); h=N.round_enc(h,sch.rounds[r],r)
            hs[r].append(sum((a^b).bit_count() for a,b in zip(N.grid_to_bytes(g),N.grid_to_bytes(h))))
    return dict(dependence_min_union=mins,full_dependence_round=next((r+1 for r,m in enumerate(mins) if m==128),None),avalanche=[dict(round=r+1,mean=sum(v)/len(v),min=min(v),max=max(v),p01=sorted(v)[2]) for r,v in enumerate(hs)])
result={'method':'dependence: Random(5), all 128 byte positions, four trials, three rounds; avalanche: Random(20261108), 300 matched inputs/nonces/bit flips, no whitening (XOR whitening does not affect distances)', 'bar_lines_only':measure(OLD),'second_coloring':measure(NEW)}
open(os.path.join(WORK,'sneak_n2','color2_comparison.json'),'w').write(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
