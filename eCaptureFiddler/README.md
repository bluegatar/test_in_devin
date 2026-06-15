# eCapture → Fiddler Classic extension

[中文教程 / Chinese tutorial](README_CN.md)

C# port of the [eCaptureBurp](../eCaptureBurp) extension for **Fiddler Classic**.
It connects to eCapture over WebSocket (eCaptureQ), parses the protobuf frames,
reassembles fragmented HTTP/1.x messages, pairs requests with responses by
`PID_TID`, de-chunks and decompresses bodies (gzip / deflate / br), and injects
each pair into Fiddler's session list as a synthetic `Session`.

- **Build:** on Windows, run `build.bat` (auto-detects Fiddler) or
  `dotnet build ECaptureFiddler.csproj -c Release /p:FiddlerPath="<Fiddler dir>"`.
  Targets .NET Framework 4.8 and references `Fiddler.exe`.
- **Install:** copy `bin\Release\ECaptureFiddler.dll` to
  `%USERPROFILE%\Documents\Fiddler2\Inspectors\`, Unblock it, restart Fiddler.
  An **eCapture** tab appears; enter `ws://<phone-ip>:28257/` and click Connect.
- **Tests:** `cd coretest && dotnet run` runs 24 offline cases covering the
  Fiddler-independent core (protobuf, parsing, reassembly, pairing, decode).

See [README_CN.md](README_CN.md) for the full build/install/usage tutorial,
the layer-by-layer troubleshooting table, and limitations (HTTP/1.x only;
Brotli unavailable on .NET Framework).
