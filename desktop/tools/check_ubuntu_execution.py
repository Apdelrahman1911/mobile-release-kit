"""Read-only CI candidate and duplicate-run admission; original API pages retained."""
import json, os, re, subprocess, urllib.request
from pathlib import Path

REPO='Apdelrahman1911/mobile-release-kit'
REF='refs/heads/verify/desktop-linux-installer-candidate-014'
WORKFLOW='.github/workflows/desktop-linux-installer-candidate.yml'
SOURCE=Path(__file__).resolve().parents[2]

def source_identity(commit,tree):
 for expression,expected in [('HEAD',commit),('HEAD^{tree}',tree)]:
  actual=subprocess.check_output(['/usr/bin/git','--git-dir='+str(SOURCE/'.git'),'--work-tree='+str(SOURCE),'rev-parse',expression],timeout=30).decode().strip()
  assert actual==expected,'Checked out source differs from the exact run'

def check(output,commit,tree):
 assert re.fullmatch('[0-9a-f]{40}',commit) and re.fullmatch('[0-9a-f]{40}',tree)
 assert os.environ['GITHUB_REPOSITORY']==REPO and os.environ['GITHUB_REF']==REF
 assert os.environ['GITHUB_EVENT_NAME']=='push' and os.environ['RUNNER_ENVIRONMENT']=='github-hosted'
 assert os.environ['GITHUB_WORKFLOW_REF']==REPO+'/'+WORKFLOW+'@'+REF
 assert os.environ['GITHUB_SHA']==commit and os.environ['GITHUB_RUN_ATTEMPT']=='1'
 assert os.environ['GITHUB_WORKFLOW_SHA']==commit
 event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
 assert event['after']==commit and event['ref']==REF and not event['deleted'] and not event['forced']
 source_identity(commit,tree)
 output.mkdir(mode=0o700)
 current=int(os.environ['GITHUB_RUN_ID']);seen=set()
 for page in range(1,11):
  url=f'https://api.github.com/repos/{REPO}/actions/runs?head_sha={commit}&per_page=100&page={page}'
  req=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
  with urllib.request.urlopen(req,timeout=30) as f:raw=f.read((8<<20)+1)
  assert len(raw)<=8<<20,'API response limit'
  (output/f'runs-{page}.json').write_bytes(raw);data=json.loads(raw)
  assert data['total_count']<=1000,'Run pagination cannot prove completeness'
  for run in data['workflow_runs']:
   assert run['head_sha']==commit and run['id'] not in seen
   seen.add(run['id'])
   if run['id']==current:
    assert run['path']==WORKFLOW and run['event']=='push' and run['run_attempt']==1
   elif run['path']==WORKFLOW:
    raise AssertionError('Candidate already executed; allocate a reviewed successor commit')
   else:
    assert run['status']=='completed','Another active run binds this candidate'
  if len(data['workflow_runs'])<100:break
 else:raise RuntimeError('Run pagination limit')
 assert current in seen,'Original current run not observed'
 (output/'request.json').write_text(json.dumps(dict(commit=commit,tree=tree,run=current,attempt=1,ref=REF,publication=False),indent=2))
if __name__=='__main__':
 import sys
 check(Path(sys.argv[1]),sys.argv[2],sys.argv[3])
