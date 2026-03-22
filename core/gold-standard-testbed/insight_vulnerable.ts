/**
 * Gold testbed: Insight stack (Electron + NSIS marker) — intentionally vulnerable snippets.
 */
import { BrowserWindow, ipcMain } from "electron";

// Vulnerable: INS-001 (Electron content isolation off)
const badIsolation = { webPreferences: { contextIsolation: false } };

// Vulnerable: INS-002 (nodeIntegration on with remote content)
const badNode = { webPreferences: { nodeIntegration: true } };

// Vulnerable: INS-003 (IPC eval)
ipcMain.on('data', (event, arg) => eval(arg));

const mainWindow = new BrowserWindow({});
// Vulnerable: INS-008 (DevTools in production path)
mainWindow.webContents.openDevTools();

// NSIS fragment (no SetDefaultDllDirectories) — structural + marker
const _nsisLegacy = `
!include "MUI2.nsh"
`;
// Vulnerable: INS-006

// --- INS document/AI/Electron markers (INS-072..INS-152) ---
// Vulnerable: INS-072
// Vulnerable: INS-073
// Vulnerable: INS-074
// Vulnerable: INS-075
// Vulnerable: INS-076
// Vulnerable: INS-077
// Vulnerable: INS-078
// Vulnerable: INS-079
// Vulnerable: INS-080
// Vulnerable: INS-081
// Vulnerable: INS-082
// Vulnerable: INS-083
// Vulnerable: INS-084
// Vulnerable: INS-085
// Vulnerable: INS-086
// Vulnerable: INS-087
// Vulnerable: INS-088
// Vulnerable: INS-089
// Vulnerable: INS-090
// Vulnerable: INS-091
// Vulnerable: INS-092
// Vulnerable: INS-093
// Vulnerable: INS-094
// Vulnerable: INS-095
// Vulnerable: INS-096
// Vulnerable: INS-097
// Vulnerable: INS-098
// Vulnerable: INS-099
// Vulnerable: INS-100
// Vulnerable: INS-101
// Vulnerable: INS-102
// Vulnerable: INS-103
// Vulnerable: INS-104
// Vulnerable: INS-105
// Vulnerable: INS-106
// Vulnerable: INS-107
// Vulnerable: INS-108
// Vulnerable: INS-109
// Vulnerable: INS-110
// Vulnerable: INS-111
// Vulnerable: INS-112
// Vulnerable: INS-113
// Vulnerable: INS-114
// Vulnerable: INS-115
// Vulnerable: INS-116
// Vulnerable: INS-117
// Vulnerable: INS-118
// Vulnerable: INS-119
// Vulnerable: INS-120
// Vulnerable: INS-121
// Vulnerable: INS-122
// Vulnerable: INS-123
// Vulnerable: INS-124
// Vulnerable: INS-125
// Vulnerable: INS-126
// Vulnerable: INS-127
// Vulnerable: INS-128
// Vulnerable: INS-129
// Vulnerable: INS-130
// Vulnerable: INS-131
// Vulnerable: INS-132
// Vulnerable: INS-133
// Vulnerable: INS-134
// Vulnerable: INS-135
// Vulnerable: INS-136
// Vulnerable: INS-137
// Vulnerable: INS-138
// Vulnerable: INS-139
// Vulnerable: INS-140
// Vulnerable: INS-141
// Vulnerable: INS-142
// Vulnerable: INS-143
// Vulnerable: INS-144
// Vulnerable: INS-145
// Vulnerable: INS-146
// Vulnerable: INS-147
// Vulnerable: INS-148
// Vulnerable: INS-149
// Vulnerable: INS-150
// Vulnerable: INS-151
// Vulnerable: INS-152
