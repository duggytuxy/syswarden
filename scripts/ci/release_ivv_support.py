"""Retain the original candidate binary bundle and SBOM across publication commits."""
import io
from pathlib import Path
import stat
import subprocess
import tarfile
import zipfile

try:
    from scripts.ci import release_ivv_current as current
    from scripts.ci import current_candidate_update_verify as updater
    from scripts.ci import release_gate
except ModuleNotFoundError:
    import release_ivv_current as current
    import current_candidate_update_verify as updater
    import release_gate

frozen=current.frozen
require,equal=current.require,current.equal
REPO='duggytuxy/syswarden'
WORKFLOW='.github/workflows/security-audit.yml'
RUN=36813024209
MAX_BYTES=128*1024*1024


def metadata(repository: Path,row: dict) -> dict:
    wire=updater.original.command(['gh','api',f"repos/{REPO}/actions/artifacts/{row['id']}"],repository)
    doc=frozen.strict_json(wire)
    for key in ('id','name','size_in_bytes','digest'):
        equal(doc[key],row[key],'original product support artifact differs: '+key)
    require(doc['expired'] is False,'original product support artifact expired')
    equal(doc['workflow_run'],dict(id=RUN,repository_id=1153695079,head_repository_id=1153695079,
          head_branch='main',head_sha=current.PRODUCT),'product support has wrong producer')
    return doc


def verify_statement(wire: bytes) -> None:
    rows=frozen.strict_json(b'{"results":'+wire+b'}')['results']
    require(type(rows) is list and len(rows)==1,'one verified product build statement required')
    result=rows[0]['verificationResult'];statement=result['statement']
    cert=result['signature']['certificate']
    equal(cert['issuer'],'https://token.actions.githubusercontent.com','wrong OIDC issuer')
    equal(cert['subjectAlternativeName'],f'https://github.com/{REPO}/{WORKFLOW}@refs/heads/main',
          'wrong product certificate identity')
    row=current.load_plan()['product_release_support'][0]['file']
    equal(statement['_type'],'https://in-toto.io/Statement/v1','wrong product statement type')
    equal(statement['subject'],[dict(name=row['path'],digest=dict(sha256=row['sha256']))],
          'product binary attestation differs')
    equal(statement['predicateType'],'https://slsa.dev/provenance/v1','wrong product provenance')
    predicate=statement['predicate'];build=predicate['buildDefinition']
    equal(build['buildType'],'https://actions.github.io/buildtypes/workflow/v1','wrong product build type')
    equal(build['externalParameters']['workflow'],dict(path=WORKFLOW,ref='refs/heads/main',
          repository='https://github.com/'+REPO),'wrong product build workflow')
    equal(build['internalParameters']['github'],dict(event_name='push',repository_id='1153695079',
          repository_owner_id='61513268',runner_environment='github-hosted'),'wrong product execution identity')
    equal(build['resolvedDependencies'],[dict(uri=f'git+https://github.com/{REPO}@refs/heads/main',
          digest=dict(gitCommit=current.PRODUCT))],'wrong product source')
    equal(predicate['runDetails']['builder']['id'],f'https://github.com/{REPO}/{WORKFLOW}@refs/heads/main',
          'wrong product builder')
    equal(predicate['runDetails']['metadata']['invocationId'],
          f'https://github.com/{REPO}/actions/runs/{RUN}/attempts/1','wrong product run or retry')


def verify(repository: Path,root: Path) -> dict:
    plan=current.load_plan();rows=plan['product_release_support']
    require(root.is_absolute() and root==root.resolve(strict=True),'unsafe product support root')
    equal({p.name for p in root.iterdir()},{r['file']['path'] for r in rows},'unexpected support inventory')
    wires={}
    for row in rows:
        metadata(repository,row)
        wires[row['file']['path']]=frozen.read_anchored(root,row['file'],MAX_BYTES)
    bundle=root/'syswarden-release.tar.gz'
    release_gate.validate_bundle(bundle);release_gate.validate_sbom(root/'syswarden-sbom.spdx.json')
    expected={r['path']:r for r in plan['product_bundle_members']};seen=set()
    with tarfile.open(fileobj=io.BytesIO(wires[bundle.name]),mode='r:gz') as archive:
        for member in archive.getmembers():
            name=release_gate.normalize_archive_name(member.name)
            if member.isdir():continue
            require(member.isfile() and name in expected and name not in seen,'unsafe binary bundle member')
            row=expected[name];equal(member.size,row['size'],'binary bundle member size differs')
            equal(frozen.digest(archive.extractfile(member).read()),row['sha256'],'binary differs from tested candidate')
            seen.add(name)
    equal(seen,set(expected),'missing tested binary or signature catalogue')
    verified=updater.original.command(['gh','attestation','verify',str(bundle),'--repo',REPO,
        '--signer-workflow',REPO+'/'+WORKFLOW,'--signer-digest',current.PRODUCT,
        '--source-digest',current.PRODUCT,'--source-ref','refs/heads/main',
        '--deny-self-hosted-runners','--format','json'],repository)
    verify_statement(verified)
    for row in rows:equal(frozen.read_anchored(root,row['file'],MAX_BYTES),wires[row['file']['path']],
                         'product support changed during verification')
    return dict(schema='syswarden-original-product-support/v1',product_candidate=current.PRODUCT,
        run_id=RUN,files=[r['file'] for r in rows],binary_members=plan['product_bundle_members'],
        original_build_attestation_verified=True,publication_authorized=False)


def fetch(repository: Path,work: Path) -> tuple[Path,dict]:
    require(work.is_absolute() and work.parent==work.parent.resolve(strict=True) and not work.exists(),
            'product support workspace must be new')
    work.mkdir(mode=0o700);root=work/'files';root.mkdir(mode=0o700)
    for row in current.load_plan()['product_release_support']:
        metadata(repository,row)
        archive=work/(str(row['id'])+'.zip')
        with archive.open('xb') as output:
            r=subprocess.run(['gh','api',f"repos/{REPO}/actions/artifacts/{row['id']}/zip"],cwd=repository,
                stdout=output,stderr=subprocess.PIPE,timeout=180)
        require(r.returncode==0,'cannot download original product support')
        wire=frozen.bundle.regular_bytes(archive,MAX_BYTES,'product support archive')
        equal(len(wire),row['size_in_bytes'],'original product archive size differs')
        equal('sha256:'+frozen.digest(wire),row['digest'],'original product archive digest differs')
        with zipfile.ZipFile(io.BytesIO(wire)) as packed:
            members=packed.infolist();require(len(members)==1,'unexpected product archive')
            member=members[0]
            equal(member.filename,row['file']['path'],'unexpected product archive file')
            equal(member.file_size,row['file']['size'],'product archive expands beyond expected size')
            require(not member.is_dir() and not member.flag_bits&1 and
                    stat.S_IFMT(member.external_attr>>16) in (0,stat.S_IFREG),'unsafe product archive entry')
            frozen.bundle.write_exclusive(root/member.filename,packed.read(member))
    return root,verify(repository,root)
