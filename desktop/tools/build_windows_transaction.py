"""Generate fixed native binding and actual WiX CA sequence from validated DATA.
Build outputs are NONSHIPPING until both native lifecycle and consumer gates pass.
Run on disposable Windows; never dispatches CI, signs, installs or publishes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
import prepare_windows_msi as prep
from windows_build_command import run_owned

NATIVE_SOURCE = 'desktop/packaging/windows/native-transaction/'
REQUIRED = {NATIVE_SOURCE + name for name in ('transaction.cpp', 'CMakeLists.txt', 'native_tests.cpp', 'Invoke-Lifecycle.ps1')}
REQUIRED |= {'desktop/tools/build_windows_transaction.py', 'desktop/tools/create_windows_validation_transform.py', 'desktop/tools/prepare_windows_transaction_run.py', 'desktop/tools/windows_build_command.py'}

def header(b):
    def string(s): return json.dumps(s, ensure_ascii=True)
    def wide(s): return 'L' + string(s.replace('/', '\\'))
    lines = ['#pragma once', '#include <array>', '#include <cstdint>',
             'struct RuntimeFile {const wchar_t* path; std::uint64_t size; const char* sha256;};']
    for name, value in [('AssemblyBinding', prep.identity(b)['assemblyBindingSha256']),
                        ('SourceCommit', b['sourceCommit']), ('SourceTree', b['sourceTree']),
                        ('RuntimeManifest', b['manifestSha256']),
                        ('PublisherSha256', b['files'][prep.PUBLISHER]['sha256'])]:
        lines.append('inline constexpr char '+name+'[] = '+string(value)+';')
    lines.append('inline constexpr wchar_t ProductCodeW[] = L\"{'+prep.identity(b)['productCode']+'}\";')
    lines.append('inline constexpr wchar_t RuntimeManifestW[] = '+wide(b['manifestSha256'])+';')
    lines.append('inline constexpr std::uint64_t PublisherSize = '+str(b['files'][prep.PUBLISHER]['size'])+'ULL;')
    rows = [(k.removeprefix('runtime/'), v) for k, v in sorted(b['files'].items()) if k.startswith('runtime/')]
    prep.need(len(rows) == 65, 'fixed native runtime roster')
    lines.append('inline constexpr std::array<RuntimeFile, 65> RuntimeFiles = {{')
    lines += ['    {'+wide(k)+', '+str(v['size'])+'ULL, '+string(v['sha256'])+'},' for k,v in rows]
    return '\n'.join(lines+['}};', ''])

def assembly(b):
    root = ET.fromstring(prep.assembly(b)); ns = '{'+prep.NS+'}'
    package = root.find(ns+'Package')
    # Keep the consumer qualification Launch=0 from the original preparation.
    # Native transaction tests exercise this same owner core directly on
    # a disposable runner; build success never silently authorizes shipping.
    for old in list(package.findall(ns+'CustomAction')): package.remove(old)
    ET.SubElement(package,ns+'MajorUpgrade',Schedule='afterInstallExecute',DowngradeErrorMessage='A newer Mobile Release Kit version is installed.')
    ET.SubElement(package,ns+'Binary',Id='MrkTransaction',SourceFile='MrkInstallerTransaction.dll')
    for action,entry in [('GuardRuntime','MrkGuard'),('PublishRuntime','MrkPublish')]:
        ET.SubElement(package,ns+'CustomAction',Id=action,BinaryRef='MrkTransaction',DllEntry=entry,
                      Execute='deferred',Impersonate='no',Return='check')
    # Start-menu entry for the installed Desktop app (per-machine; HKLM key path).
    # Shortcut only: it launches the same installed executable, adds no rights.
    menu=ET.SubElement(package,ns+'StandardDirectory',Id='ProgramMenuFolder')
    shortcut=ET.SubElement(menu,ns+'Component',Id='CStartMenuShortcut',Guid=str(prep.uuid.uuid5(prep.NAMESPACE,'component:start-menu-shortcut')).upper(),Bitness='always64')
    ET.SubElement(shortcut,ns+'Shortcut',Id='MRKStartMenuShortcut',Name='Mobile Release Kit',Description='Prepare and release mobile apps',
                  Target='[MRKApp]'+prep.SHELL,WorkingDirectory='MRKApp')
    ET.SubElement(shortcut,ns+'RegistryValue',Root='HKLM',Key='Software\\Mobile Release Kit',Name='StartMenuShortcut',Type='integer',Value='1',KeyPath='yes')
    ET.SubElement(package.find(ns+'Feature'),ns+'ComponentRef',Id='CStartMenuShortcut')
    seq=ET.SubElement(package,ns+'InstallExecuteSequence')
    # Guard runs for install, uninstall, repair and RemoveExistingProducts child
    # sessions, before any MSI-managed file mutation. No rollback action ever
    # deletes a published version or rewrites its completion record.
    ET.SubElement(seq,ns+'Custom',Action='GuardRuntime',Before='ProcessComponents',Condition='1')
    ET.SubElement(seq,ns+'Custom',Action='PublishRuntime',After='InstallFiles',Condition='NOT REMOVE~="ALL"')
    ET.indent(root)
    return ET.tostring(root,encoding='unicode',xml_declaration=True)+'\n'

VS_GENERATORS = {17: 'Visual Studio 17 2022', 18: 'Visual Studio 18 2026'}

def visual_studio():
    """Select the hosted Visual Studio C++ installation (2022 or 2026 only).

    Hosted windows-2025 images moved from Visual Studio 2022 to 2026 (run
    43651087120). Keep the v143 toolset when it is installed; otherwise use
    that installation's default toolset. The choice is recorded as evidence.
    """
    import os, re, subprocess
    vswhere = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
    prep.need(vswhere.is_file(), 'vswhere missing')
    found = subprocess.run([str(vswhere), '-latest', '-products', '*', '-requires',
                            'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-format', 'json', '-utf8'],
                           capture_output=True, timeout=60, check=True).stdout
    rows = json.loads(found)
    prep.need(isinstance(rows, list) and len(rows) == 1, 'exactly one Visual Studio C++ installation required')
    version = str(rows[0].get('installationVersion', ''))
    prep.need(re.fullmatch(r'\d+\.\d+\.\d+(\.\d+)?', version) is not None, 'Visual Studio version unreadable')
    major = int(version.split('.')[0])
    prep.need(major in VS_GENERATORS, 'unsupported Visual Studio major version: ' + version)
    tools = Path(rows[0]['installationPath'])/'VC/Tools/MSVC'
    msvc = sorted(p.name for p in tools.iterdir() if p.is_dir())
    v143 = any(re.fullmatch(r'14\.(3\d|4\d)\.\d+', name) for name in msvc)
    return {'generator': VS_GENERATORS[major], 'installationVersion': version,
            'installationPath': rows[0]['installationPath'], 'msvc': msvc, 'toolset': 'v143' if v143 else None}

def configure_args(vs, source, build, binding_directory=None):
    args = ['cmake', '-S', str(source), '-B', str(build), '-G', vs['generator'], '-A', 'x64']
    if vs['toolset']: args += ['-T', vs['toolset']]
    args.append('-DCMAKE_SYSTEM_VERSION=10.0.26100.0')
    if binding_directory is not None: args.append('-DMRK_BINDING_DIRECTORY=' + str(binding_directory))
    return args

def generate(source, inputs, binding, expected, output):
    b = prep.validate(source, inputs, binding, expected)
    prep.need(REQUIRED <= b['sourceFiles'].keys(), 'native source binding incomplete')
    prep.prepare(source, inputs, binding, expected, output)
    (output/'binding.h').write_text(header(b))
    (output/'Package.wxs').write_text(assembly(b))
    return b

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','inputs','binding','binding-sha256','output'): p.add_argument('--'+n,required=True)
    p.add_argument('--compile',action='store_true')
    a=p.parse_args(); out=Path(a.output).absolute(); src=Path(a.source).absolute()
    generate(src,Path(a.inputs).absolute(),Path(a.binding).absolute(),a.binding_sha256,out)
    if a.compile:
        import os
        def run(name,args,timeout=600,limit=32*1024*1024): return run_owned(name,args,cwd=out,env=os.environ.copy(),logs=out/'command-logs',timeout=timeout,limit=limit)
        vs=visual_studio(); (out/'visual-studio.json').write_text(json.dumps(vs,indent=2)+'\n')
        run('cmake-configure',configure_args(vs,src/NATIVE_SOURCE,'native-build',out))
        run('cmake-build',['cmake','--build','native-build','--config','Release','--parallel','1'])
        import shutil
        shutil.copyfile(out/'native-build/Release/MrkInstallerTransaction.dll',out/'MrkInstallerTransaction.dll')
        toolchain={}
        for tool in ('cmake','wix','python','cargo','rustc','node','npm'):
            selected=Path(shutil.which(tool) or '')
            prep.need(selected.is_file(),'selected build tool missing')
            toolchain[tool]={'path':str(selected),'sha256':hashlib.sha256(selected.read_bytes()).hexdigest()}
            flags=['-Vv'] if tool=='rustc' else ['--version']
            run('version-'+tool,[str(selected),*flags],timeout=15,limit=16384)
            version=(out/'command-logs'/('version-'+tool+'.stdout')).read_text()
            prep.need(len(version)<16384,'tool version output bound')
            toolchain[tool]['version']=version
            expected={'cmake':'cmake version 4.3.4','wix':'4.0.6','python':'Python 3.14.7','cargo':'cargo 1.98.0','rustc':'rustc 1.98.0','node':'v24.20.0'}.get(tool)
            prep.need(expected is None or version.startswith(expected),'selected tool version differs: '+tool)
        compiler=list((out/'native-build/CMakeFiles').glob('*/CMakeCXXCompiler.cmake'))
        prep.need(len(compiler)==1,'unique native compiler receipt required')
        toolchain['cmakeCompilerReceipt']=compiler[0].read_text()
        import re
        match=re.search(r'set\(CMAKE_CXX_COMPILER "([^"]+)"\)',toolchain['cmakeCompilerReceipt'])
        prep.need(match is not None,'compiler path missing')
        cl=Path(match[1]);toolchain['cl']={'path':str(cl),'sha256':hashlib.sha256(cl.read_bytes()).hexdigest()}
        (out/'toolchain.json').write_text(json.dumps(toolchain,indent=2)+'\n')
        # Tool version is pinned by the launch workflow. The Launch=0 shipping
        # gate remains present in this actual MSI and is asserted after decompile.
        run('wix-build',['wix','build','Package.wxs','-arch','x64','-o','MobileReleaseKit-NONSHIPPING.msi'])
        run('validation-transform',['python',str(src/'desktop/tools/create_windows_validation_transform.py'),'--msi',str(out/'MobileReleaseKit-NONSHIPPING.msi'),'--transform',str(out/'DISPOSABLE-VALIDATION-ONLY.mst')])
        artifacts={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in
                   ('MrkInstallerTransaction.dll','MobileReleaseKit-NONSHIPPING.msi','DISPOSABLE-VALIDATION-ONLY.mst','binding.h','Package.wxs')}
        (out/'native-build-result.json').write_text(json.dumps({'artifacts':artifacts,'shippingGate':False,
            'nativeLifecycleAccepted':False,'signatureVerified':False},indent=2)+'\n')
if __name__=='__main__': main()
