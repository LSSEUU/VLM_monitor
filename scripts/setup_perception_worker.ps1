$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workerRoot = Join-Path $projectRoot ".venv-perception"
$workerPython = Join-Path $workerRoot "Scripts\python.exe"
$requirements = Join-Path $projectRoot "requirements\perception-worker.txt"
$modelId = "IDEA-Research/grounding-dino-tiny"
$revision = "a2bb814dd30d776dcf7e30523b00659f4f141c71"
$expectedWeightSha256 = "1a2412ef99bd74bcd3c2a246fa1e48581f8889a1300c9051974741314fc042f3"
$poseModelId = "usyd-community/vitpose-plus-small"
$poseRevision = "0c30b6534bb621af0162b481176742577264e36e"
$poseExpectedWeightSha256 = "f7bad8ed09eeeb2a7de6b38faaa8a88d07838e23e9c06a2a782099bca7467cb9"

function Assert-NativeSuccess {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    throw "uv is required to create the isolated perception environment"
}

Push-Location $projectRoot
try {
    uv venv --python 3.11 --allow-existing $workerRoot
    Assert-NativeSuccess "creating the perception virtual environment"
    uv pip install --python $workerPython torch==2.8.0 `
        --index-url https://download.pytorch.org/whl/cu128
    Assert-NativeSuccess "installing CUDA PyTorch"
    uv pip install --python $workerPython --requirement $requirements
    Assert-NativeSuccess "installing perception dependencies"
    uv pip install --python $workerPython --editable .
    Assert-NativeSuccess "installing LabCourt into the perception environment"

    $downloadCode = @"
from huggingface_hub import snapshot_download
import sys
snapshot_download(sys.argv[1], revision=sys.argv[2])
"@
    & $workerPython -c $downloadCode $modelId $revision
    Assert-NativeSuccess "downloading the pinned Grounding DINO snapshot"
    & $workerPython -c $downloadCode $poseModelId $poseRevision
    Assert-NativeSuccess "downloading the pinned ViTPose snapshot"

    $verifyCode = @"
from hashlib import sha256
from pathlib import Path
from transformers.utils.hub import cached_file
import sys
path = cached_file(sys.argv[1], 'model.safetensors', revision=sys.argv[2], local_files_only=True)
hasher = sha256()
with Path(path).open('rb') as source:
    while chunk := source.read(1024 * 1024):
        hasher.update(chunk)
digest = hasher.hexdigest()
if digest != sys.argv[3]:
    raise SystemExit('downloaded perception weight SHA-256 mismatch')
import torch
if not torch.cuda.is_available():
    raise SystemExit('CUDA is unavailable in the isolated perception environment')
print(f'perception environment ready; torch={torch.__version__}; device={torch.cuda.get_device_name(0)}')
"@
    & $workerPython -c $verifyCode $modelId $revision $expectedWeightSha256
    Assert-NativeSuccess "verifying the Grounding DINO environment"
    & $workerPython -c $verifyCode $poseModelId $poseRevision $poseExpectedWeightSha256
    Assert-NativeSuccess "verifying the ViTPose environment"

    $handshakeCode = @"
import subprocess
import sys
import json
result = subprocess.run(
    [sys.executable, '-u', '-m', 'labcourt.perception_worker', '--config', sys.argv[1]],
    input=b'',
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    timeout=360,
    check=False,
)
ready = result.stdout.decode('utf-8').strip()
try:
    payload = json.loads(ready)
except (UnicodeError, ValueError):
    payload = {}
if result.returncode != 0 or payload.get('kind') != 'READY':
    raise SystemExit('perception worker did not produce a valid READY handshake')
print(ready)
"@
    & $workerPython -c $handshakeCode (Join-Path $projectRoot "configs\pilot.yaml")
    Assert-NativeSuccess "checking the perception worker READY handshake"
}
finally {
    Pop-Location
}
