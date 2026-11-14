"""Fixed original Cargo output admission/retention for the MSI consumer successor.
DATA verification only. No installation, launch authority or native qualification.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import shutil
import tomllib
import ci_foundation as foundation

LIMIT = 16 * 1024 * 1024
TARGET = 'x86_64-pc-windows-msvc'

def need(value, tag):
    if not value: raise ValueError('compiler-evidence:'+tag)

def _output_facts(details):
    return {'regular':stat.S_ISREG(details.st_mode),'links':details.st_nlink,'bytes':details.st_size,
            'attributes':getattr(details,'st_file_attributes',0),'reparseTag':getattr(details,'st_reparse_tag',0),
            'volume':details.st_dev,'fileId':details.st_ino}

def _output_state(details):
    return (details.st_dev,details.st_ino,stat.S_IFMT(details.st_mode),details.st_nlink,details.st_size,details.st_mtime_ns)

def compiler_output_record(path,*,binary,limit,logs,role):
    """Acquire one ACTUAL Cargo release output under the compiler-output role.

    Cargo publishes ("uplifts") target/<triple>/release/<bin>.exe as a hard link
    to its own target/<triple>/release/deps/<crate>-<metadata>.exe when the
    filesystem permits. The installed-file reader correctly refuses any second
    link, so it is not used for this role and is not relaxed. This reader admits
    a regular, non-reparse output with either one link, or exactly two links
    whose sole other name is a regular file inside this build's own Cargo target
    directory (same volume and file ID). A second name anywhere else is refused.
    Original metadata is retained before any decision.
    """
    before=path.lstat();facts={'role':role,'path':str(path),'original':_output_facts(before),'counterparts':[]}
    # Cargo's internal build directory layout varies by release (run 43631131903
    # with Cargo 1.98 had no partner in release/deps). Search the bounded target
    # tree for the other name of this same file (same volume and file ID).
    target_root=path.parents[2]
    partners=[];scanned=0
    if before.st_nlink==2:
        for root,dirs,files in os.walk(target_root):
            dirs.sort()
            for name in sorted(files):
                scanned+=1;need(scanned<=400000,'compiler-output-scan-bound')
                entry=Path(root)/name
                if entry==path:continue
                details=entry.lstat()
                if details.st_size!=before.st_size or not stat.S_ISREG(details.st_mode):continue
                row={'path':str(entry.relative_to(target_root)),**_output_facts(details)};facts['counterparts'].append(row)
                if (details.st_dev,details.st_ino)==(before.st_dev,before.st_ino):partners.append((entry,details))
    facts['scannedFiles']=scanned
    logs.mkdir(exist_ok=True)
    (logs/(role+'-compiler-output-metadata.json')).write_text(json.dumps(facts,indent=2,sort_keys=True)+'\n')
    need(stat.S_ISREG(before.st_mode) and not getattr(before,'st_file_attributes',0)&0x400
         and not getattr(before,'st_reparse_tag',0),'compiler-output-ordinary')
    need(before.st_nlink==1 or (before.st_nlink==2 and len(partners)==1),'compiler-output-links')
    need(0<before.st_size<=limit,'compiler-output-bound')
    with path.open('rb') as stream:
        opened=os.fstat(stream.fileno())
        need((opened.st_dev,opened.st_ino,opened.st_size,opened.st_nlink)==(before.st_dev,before.st_ino,before.st_size,before.st_nlink),'compiler-output-open')
        value=stream.read(before.st_size+1)
        after=os.fstat(stream.fileno())
        need((after.st_dev,after.st_ino,after.st_size,after.st_nlink,after.st_mtime_ns)==(opened.st_dev,opened.st_ino,opened.st_size,opened.st_nlink,opened.st_mtime_ns),'compiler-output-read')
    need(len(value)==before.st_size and _output_state(path.lstat())==_output_state(before),'compiler-output-changed')
    for entry,details in partners:need(_output_state(entry.lstat())==_output_state(details),'compiler-output-partner-changed')
    return {'size':len(value),'sha256':hashlib.sha256(value).hexdigest(),'links':before.st_nlink,
            'cargoOriginal':str(partners[0][0].relative_to(target_root)) if partners else None}

def selected_artifact(raw, *, role, source, output):
    """Select only the actual final compiler event, never a predicted path alone."""
    need(role in ('publisher','shell'), 'role')
    need(isinstance(raw,bytes) and 0<len(raw)<=LIMIT, 'stream-bound')
    lines=raw.splitlines();need(0<len(lines)<=8192,'message-count')
    binary='mrk-windows-runtime-publish' if role=='publisher' else 'mobile-release-kit-desktop'
    src=source/'desktop/src-tauri/src'/('bin/windows_runtime_publish.rs' if role=='publisher' else 'main.rs')
    features=['windows-runtime-publisher'] if role=='publisher' else ['custom-protocol','desktop-shell']
    expected=output/'target'/TARGET/'release'/(binary+'.exe')
    selected=None;finished=False;units=0
    for line in lines:
        need(len(line)<=2*1024*1024,'message-bound')
        row=foundation.bounded_json(line,2*1024*1024);need(isinstance(row,dict) and not finished,'message-order')
        reason=row.get('reason');need(reason in ('compiler-artifact','compiler-message','build-script-executed','build-finished'),'message-kind')
        if reason=='build-finished':
            need(row.get('success') is True,'original-build-finished');finished=True;continue
        if reason=='compiler-message':
            need(isinstance(row.get('message'),dict) and row['message'].get('level')!='error','compiler-error')
        if reason!='compiler-artifact':continue
        units+=1
        target=row.get('target');need(isinstance(target,dict),'target')
        if row.get('manifest_path')!=str(source/'desktop/src-tauri/Cargo.toml') or target.get('name')!=binary or target.get('kind')!=['bin']:continue
        profile=row.get('profile');need(selected is None and isinstance(profile,dict),'unique-final-artifact')
        need(target.get('src_path')==str(src) and row.get('features')==features and profile.get('test') is False
             and profile.get('debug_assertions') is False and profile.get('opt_level')=='3' and target.get('crate_types')==['bin']
             and row.get('fresh') is False,'actual-release-role')
        need(row.get('executable')==str(expected) and str(expected) in row.get('filenames',[]),'actual-executable-path')
        selected=expected
    need(finished and selected is not None and units>0,'complete-original-stream')
    need(selected.is_file(),'original-artifact-missing')
    original=compiler_output_record(selected,binary=binary,limit=512<<20,logs=output/'logs',role=role)
    return {'path':str(selected),'bytes':original['size'],'sha256':original['sha256'],
            'compilerStreamBytes':len(raw),'compilerStreamSha256':hashlib.sha256(raw).hexdigest(),'compilerUnits':units,
            'role':role,'features':features,'profile':'release','debugAssertions':False}

def material_graph(metadata,lock,*,source,output):
    """Locate original material sources for retention, without qualifying a GUI graph.

    The historical GUI validator binds a different app version and dependency
    graph. Keep it unchanged. A current consumer must validate the complete
    retained metadata and release-unit stream before any native acceptance.
    """
    registry='registry+https://github.com/rust-lang/crates.io-index'
    need(isinstance(lock,dict) and lock.get('version')==4
         and isinstance(lock.get('package'),list) and 4<=len(lock['package'])<=2048,'lock-inventory')
    locked={}
    for row in lock['package']:
        need(isinstance(row,dict) and isinstance(row.get('name'),str)
             and isinstance(row.get('version'),str),'lock-identity')
        key=(row['name'],row['version'],row.get('source'))
        need(key not in locked and (key[2] is None or key[2]==registry
             and foundation.sha256_value(row.get('checksum'))),'lock-source')
        locked[key]=row
    need(isinstance(metadata,dict) and metadata.get('version')==1
         and isinstance(metadata.get('packages'),list) and 4<=len(metadata['packages'])<=1024
         and metadata.get('workspace_root')==str(source/'desktop/src-tauri')
         and metadata.get('target_directory')==str(output/'target'),'metadata-inventory')
    packages={};identities={}
    for package in metadata['packages']:
        need(isinstance(package,dict) and isinstance(package.get('id'),str)
             and 0<len(package['id'])<=4096 and isinstance(package.get('name'),str)
             and isinstance(package.get('version'),str),'metadata-identity')
        key=(package['name'],package['version'],package.get('source'))
        need(key in locked and key not in identities and package['id'] not in packages,'metadata-lock-binding')
        packages[package['id']]=package;identities[key]=package['id']
    material={}
    for name,version in foundation.WINDOWS_NORMAL_UI_MATERIAL_PACKAGES.items():
        key=(name,version,registry);need(key in identities,'material-source-identity')
        ident=identities[key];package=packages[ident];spelling=package.get('manifest_path')
        need(isinstance(spelling,str) and 0<len(spelling)<=16384,'material-manifest')
        path=Path(spelling);base=output/'cargo/registry/src'
        need(path.is_absolute() and path.is_relative_to(base) and len(path.relative_to(base).parts)==3
             and not any(part in ('.','..') for part in spelling.replace('\\','/').split('/'))
             and path.parent.name==name+'-'+version and path.name=='Cargo.toml','material-private-source')
        material[name]=ident
    return {'packages':packages,'materialIds':material}

def retain_normal(source,output,selected):
    """Retain exactly the originals required by existing UI graph/link validators."""
    logs=output/'logs';raw=(logs/'shell-metadata.stdout').read_bytes();need(0<len(raw)<=LIMIT,'metadata-bound')
    metadata=foundation.bounded_json(raw,LIMIT,max_nodes=200000)
    graph=material_graph(metadata,tomllib.loads((source/'desktop/src-tauri/Cargo.lock').read_text()),source=source,output=output)
    # Retain lock-bound originals and exact pinned material bytes, not a graph qualification.
    material=foundation.windows_normal_ui_material_sources(graph)
    packages=graph['packages'];ids=graph['materialIds']
    tauri=Path(packages[ids['tauri-build']]['manifest_path']).parent
    webview=Path(packages[ids['webview2-com-sys']]['manifest_path']).parent
    paths={'commonControlsTemplate':tauri/'src/windows-app-manifest.xml','webviewBuild':webview/'build.rs',
           'webviewLinkSelection':webview/'src/lib.rs','webviewBindings':webview/'src/bindings.rs',
           'webviewX64StaticLibrary':webview/'x64/WebView2LoaderStatic.lib'}
    # Select the target library from the actual original build-script event.
    rows=[]
    for line in (logs/'shell-compile.stdout').read_bytes().splitlines():
        row=foundation.bounded_json(line,2*1024*1024)
        if row.get('reason')=='build-script-executed' and row.get('package_id')==ids['webview2-com-sys']:rows.append(row)
    need(len(rows)==1,'unique-original-webview-output');row=rows[0];outdir=Path(row.get('out_dir',''))
    need(outdir.is_absolute() and outdir.parent.parent==output/'target'/TARGET/'release/build'
         and outdir.name=='out' and row.get('linked_libs')==['advapi32']
         and row.get('linked_paths')==['native='+str(outdir/'x64')],'actual-webview-link-selection')
    actual=outdir/'x64/WebView2LoaderStatic.lib'
    need(foundation.windows_installed_record(actual,32<<20)==material['webviewX64StaticLibrary'],'actual-target-loader-bytes')
    paths['actualTargetStaticLibrary']=actual
    retained=output/'consumer-evidence';retained.mkdir()
    records={}
    for role,path in paths.items():
        raw=foundation.windows_installed_bytes(path,32<<20);need(0<len(raw)<=32<<20,'material-original-bound')
        dest=retained/role;dest.write_bytes(raw)
        records[role]={'originalPath':str(path),'retainedPath':role,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    for name in ('shell-metadata.stdout','shell-metadata.result.json','shell-compile.stdout','shell-compile.stderr','shell-compile.result.json'):
        shutil.copyfile(logs/name,retained/name)
    envelope={'schema':1,'sourcePath':str(source),'outputPath':str(output),'target':TARGET,'profile':'release',
              'normalArtifact':selected,'materials':records,'metadataSha256':hashlib.sha256((logs/'shell-metadata.stdout').read_bytes()).hexdigest(),
              'nativeConsumerQualified':False,'normalGraphValidated':False,'materialSourcePinsValidated':True,
              'releaseUnitGraphConsumerValidation':'required-by-current65-adapter; original metadata and stream retained'}
    (retained/'compiler-context.json').write_text(json.dumps(envelope,sort_keys=True,indent=2)+'\n')
    return envelope
