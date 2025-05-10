# dollarnine
a self managed worm powered by a rootkit

> "educational purposes only" of course

## overview
basically a reverse shell that uses detours for api calls, and has ~a stable~ modified version of the `dollarnine` rootkit. once the program is ran, it starts to inject `dollarnine.dll` into `explorer.exe`. after that, it installs a copy of itself into the system, or if already installed, updated itself. it automatically adds the newly installed/updated copy into the Startup Apps, once done, it start to iterate connection tries to the commander.


### rootkit
juicy ring3!

if the file starts with `$9`, it hides:
- [x] TCP & UDP connections
- [ ] created files directories
- [x] processes & CPU/GPU usage
- [ ] registry keys & values
- [x] services
- [ ] proper server without netcat
- [ ] junctions, named pipes, scheduled tasks

with that, we rename our dropped file to `$9dollarnine.exe`.

## future/past

- [x] use powershell
- [ ] switch option for powershell/cmd
- [ ] make a normal controller server interface

