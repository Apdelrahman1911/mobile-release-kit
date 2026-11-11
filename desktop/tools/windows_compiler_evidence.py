"""Fixed original Cargo output admission/retention for the MSI consumer successor.
DATA verification only. No installation, launch authority or native qualification.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import tomllib
import ci_foundation as foundation

LIMIT = 16 * 1024 * 1024
TARGET = 'x86_64-pc-windows-msvc'

def need(value, tag):
    if not value: raise ValueError('compiler-evidence:'+tag)

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
    original=foundation.windows_installed_record(selected,512<<20)
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
