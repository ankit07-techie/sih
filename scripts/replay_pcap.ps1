# PassiveShield AI — PCAP Replay Execution Wrapper (PowerShell)

param (
    [string]$Pcap = "fixtures/sample_replay.pcap",
    [double]$Speed = 1.0,
    [int]$Loop = 1,
    [switch]$DryRun
)

$cmdArgs = @("replay/replay_runner.py", "--pcap", $Pcap, "--speed", $Speed.ToString(), "--loop", $Loop.ToString())
if ($DryRun) {
    $cmdArgs += "--dry-run"
}

py -3 @cmdArgs
