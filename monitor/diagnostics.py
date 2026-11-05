"""
Read-only diagnostics for Windows Event Log accessibility, audit policies,
and platform compatibility.
All checks are non-invasive and strictly read-only.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from typing import Any, Optional


def check_pywin32_compatibility() -> dict[str, Any]:
    """
    Verify actual runtime pywin32 compatibility with the current Python environment.
    Performs dynamic imports and checks core event log modules.
    """
    result: dict[str, Any] = {
        "is_compatible": False,
        "pywin32_available": False,
        "version": None,
        "modules_loaded": [],
        "error": None,
    }

    if sys.platform != "win32":
        result["error"] = f"Operating system is {sys.platform}, not Windows (win32)."
        return result

    loaded_modules = []
    try:
        import win32api
        loaded_modules.append("win32api")
        import win32evtlog
        loaded_modules.append("win32evtlog")
        import win32security
        loaded_modules.append("win32security")

        # Probe version if available
        version = getattr(win32api, "GetFileVersionInfo", None)
        result["pywin32_available"] = True
        result["is_compatible"] = True
        result["modules_loaded"] = loaded_modules

        # Query installed package version if possible
        try:
            import importlib.metadata
            result["version"] = importlib.metadata.version("pywin32")
        except Exception:
            result["version"] = "available"

    except ImportError as exc:
        result["error"] = f"Failed to import pywin32 modules: {exc}"
    except Exception as exc:
        result["error"] = f"Unexpected error checking pywin32: {exc}"

    return result


def check_channel_accessibility(channel_name: str) -> dict[str, Any]:
    """
    Perform a strictly read-only check on a Windows Event Log channel.
    Tests accessibility without modifying or clearing any logs.
    """
    result: dict[str, Any] = {
        "channel": channel_name,
        "accessible": False,
        "status": "UNAVAILABLE",
        "details": "",
        "error_code": None,
    }

    if sys.platform != "win32":
        result["status"] = "NOT_WINDOWS"
        result["details"] = "Windows Event Log is only available on Windows operating systems."
        return result

    try:
        import win32evtlog
    except ImportError:
        result["status"] = "MODULE_MISSING"
        result["details"] = "pywin32 (win32evtlog) is not installed."
        return result

    # Test access using modern EvtQuery in read-only channel mode
    try:
        query_handle = win32evtlog.EvtQuery(
            channel_name,
            win32evtlog.EvtQueryChannelPath
        )
        result["accessible"] = True
        result["status"] = "ONLINE"
        result["details"] = f"Channel '{channel_name}' is accessible for read-only monitoring."
        return result
    except Exception as evt_exc:
        error_code = getattr(evt_exc, "winerror", None)
        if error_code is None and hasattr(evt_exc, "args") and evt_exc.args:
            if isinstance(evt_exc.args[0], int):
                error_code = evt_exc.args[0]

        result["error_code"] = error_code

        # Error 5 is ERROR_ACCESS_DENIED
        if error_code == 5 or "Access is denied" in str(evt_exc):
            result["status"] = "ACCESS_DENIED"
            if channel_name.lower() == "security":
                result["details"] = (
                    "Access is denied. Reading the Windows Security log requires elevated "
                    "privileges or membership in the 'Event Log Readers' group."
                )
            else:
                result["details"] = f"Access denied to channel '{channel_name}'."
            return result

        # Fallback probe using classic OpenEventLog for backward-compatible channels
        try:
            classic_handle = win32evtlog.OpenEventLog(None, channel_name)
            if classic_handle:
                win32evtlog.CloseEventLog(classic_handle)
                result["accessible"] = True
                result["status"] = "ONLINE"
                result["details"] = f"Channel '{channel_name}' is accessible via classic EventLog API."
                result["error_code"] = None
                return result
        except Exception as classic_exc:
            classic_code = getattr(classic_exc, "winerror", None)
            if classic_code is None and hasattr(classic_exc, "args") and classic_exc.args:
                if isinstance(classic_exc.args[0], int):
                    classic_code = classic_exc.args[0]
            result["error_code"] = classic_code or error_code

        result["status"] = "ERROR"
        result["details"] = f"Unable to open channel '{channel_name}': {evt_exc}"
        return result


def check_all_channels(channels: Optional[list[str]] = None) -> dict[str, dict[str, Any]]:
    """Test read-only accessibility across multiple Windows Event Log channels."""
    if channels is None:
        channels = ["Security", "System", "Application"]
    return {ch: check_channel_accessibility(ch) for ch in channels}


def check_audit_policy(subcategory: str = "Logon") -> dict[str, Any]:
    """
    Perform a strictly read-only check of the Windows audit policy for a subcategory.
    Does not modify or set any policies.
    """
    result: dict[str, Any] = {
        "subcategory": subcategory,
        "accessible": False,
        "auditing_enabled": False,
        "status": "AUDIT_STATUS_UNVERIFIED",
        "setting": "Unknown",
        "details": "",
    }

    if sys.platform != "win32":
        result["status"] = "NOT_WINDOWS"
        result["details"] = "Audit policy checks are only supported on Windows."
        return result

    try:
        proc = subprocess.run(
            ["auditpol", "/get", f"/subcategory:{subcategory}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        combined = stdout + stderr

        # Check for access denied (Error 0x00000005)
        if proc.returncode != 0 or "Access is denied" in combined or "0x00000005" in combined:
            result["status"] = "AUDIT_STATUS_UNVERIFIED"
            result["details"] = (
                "Audit policy query returned Access Denied. Querying audit policies with 'auditpol' "
                "requires administrative elevation. Detection will still operate if auditing was "
                "previously enabled by policy."
            )
            return result

        # Parse auditpol table output
        # Format typical output:
        # System audit policy
        # Category/Subcategory                      Setting
        # Logon                                     Success and Failure
        result["accessible"] = True
        found_setting = None
        for line in stdout.splitlines():
            if subcategory.lower() in line.lower():
                parts = line.strip().split("  ")
                parts = [p.strip() for p in parts if p.strip()]
                if len(parts) >= 2:
                    found_setting = parts[-1]
                    break

        if found_setting:
            result["setting"] = found_setting
            setting_lower = found_setting.lower()
            if "success and failure" in setting_lower:
                result["auditing_enabled"] = True
                result["status"] = "AUDIT_ACTIVE"
                result["details"] = "Auditing is fully enabled for both Success and Failure events."
            elif "failure" in setting_lower:
                result["auditing_enabled"] = True
                result["status"] = "AUDIT_PARTIAL"
                result["details"] = "Auditing is enabled for Failure events only (logon failures will be recorded)."
            elif "success" in setting_lower:
                result["auditing_enabled"] = False
                result["status"] = "AUDIT_INSUFFICIENT"
                result["details"] = (
                    "Auditing is enabled for Success events only. Windows will NOT record Event ID 4625 "
                    "(Logon Failure) under this policy configuration."
                )
            elif "no auditing" in setting_lower:
                result["auditing_enabled"] = False
                result["status"] = "AUDIT_DISABLED"
                result["details"] = (
                    "Auditing is disabled ('No Auditing'). The Windows OS is not logging logon events."
                )
            else:
                result["status"] = "AUDIT_UNKNOWN"
                result["details"] = f"Audit policy setting reported as: {found_setting}."
        else:
            result["status"] = "AUDIT_NOT_FOUND"
            result["details"] = f"Subcategory '{subcategory}' was not found in auditpol output."

    except FileNotFoundError:
        result["status"] = "TOOL_NOT_FOUND"
        result["details"] = "'auditpol.exe' is not available on system PATH."
    except subprocess.TimeoutExpired:
        result["status"] = "TIMEOUT"
        result["details"] = "Timed out waiting for auditpol query."
    except Exception as exc:
        result["status"] = "ERROR"
        result["details"] = f"Failed to execute audit policy diagnostic: {exc}"

    return result


def get_system_diagnostics() -> dict[str, Any]:
    """
    Produce a comprehensive, read-only diagnostic report of the host environment,
    channel permissions, and audit policy status.
    """
    pywin32_info = check_pywin32_compatibility()
    channels = check_all_channels()
    audit_info = check_audit_policy("Logon")

    # Assess overall live monitoring readiness
    security_accessible = channels.get("Security", {}).get("accessible", False)
    any_channel_accessible = any(ch.get("accessible", False) for ch in channels.values())

    if security_accessible:
        readiness = "READY_FULL"
        guidance = "All security monitoring channels are accessible."
    elif any_channel_accessible:
        readiness = "READY_PARTIAL"
        guidance = (
            "System/Application channels are accessible. Security channel is restricted. "
            "You can monitor system events or switch to Demo/Sample mode for full security testing."
        )
    else:
        readiness = "SAMPLE_ONLY"
        guidance = (
            "Windows Event Log channels are restricted or inaccessible. "
            "Please use Sample Replay or Static Sample mode."
        )

    return {
        "platform": {
            "os": platform.system(),
            "release": platform.release(),
            "python_version": sys.version.split()[0],
            "executable": sys.executable,
        },
        "pywin32": pywin32_info,
        "channels": channels,
        "audit_policy": audit_info,
        "readiness": readiness,
        "guidance": guidance,
    }
